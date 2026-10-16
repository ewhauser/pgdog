//! pgDog plugins.

use once_cell::sync::OnceCell;
use pgdog_config::{Config, LogFormat, Plugin as PluginConfig};
use pgdog_plugin::libloading::Library;
use pgdog_plugin::{Capabilities, Config as PdConfig, PdStr, PluginVtable};
use semver::Version;
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

use crate::backend::Schema;

static LIBS: OnceCell<Vec<Option<Library>>> = OnceCell::new();
static PLUGINS: OnceCell<Plugins> = OnceCell::new();
static SCHEMA_EPOCH: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("required plugin \"{name}\" failed to load: {reason}")]
    Required { name: String, reason: String },
}

/// A plugin that passed version checks and accepted its configuration.
#[derive(Debug)]
pub(crate) struct LoadedPlugin {
    name: String,
    vtable: &'static PluginVtable,
    capabilities: Capabilities,
}

impl LoadedPlugin {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn vtable(&self) -> &'static PluginVtable {
        self.vtable
    }

    pub(crate) fn has(&self, capability: Capabilities) -> bool {
        self.capabilities.contains(capability)
    }
}

/// Loaded plugins, in the order they appear in the config.
#[derive(Debug, Default)]
struct Plugins {
    list: Vec<LoadedPlugin>,
    /// Union of all plugins' capabilities.
    capabilities: Capabilities,
}

// Compare semantic versions by major and minor only (ignore patch/bugfix).
fn same_major_minor(a: &str, b: &str) -> bool {
    match (Version::parse(a), Version::parse(b)) {
        (Ok(va), Ok(vb)) => va.major == vb.major && va.minor == vb.minor,
        _ => {
            warn!("failed to parse plugin API version(s) ('{a}' or '{b}'), skipping plugin",);
            false
        }
    }
}

/// Why a plugin wasn't loaded, and whether PgDog may start without it.
struct LoadFailure {
    reason: String,
    required: bool,
}

/// Load plugins.
///
/// # Safety
///
/// This should be run before Tokio is loaded since this is not thread-safe.
///
pub(crate) fn load(config: &Config) -> Result<(), Error> {
    if LIBS.get().is_some() {
        return Ok(());
    };

    let plugins = &config.plugins;

    let libs = plugins
        .iter()
        .map(|plugin| {
            PluginVtable::library(&plugin.name)
                .map_err(|err| error!("plugin \"{}\" failed to load: {:#?}", plugin.name, err))
                .ok()
        })
        .collect();

    let _ = LIBS.set(libs);

    let mut loaded = Plugins::default();
    let mut required_failure = None;

    for (plugin, lib) in plugins.iter().zip(LIBS.get().into_iter().flatten()) {
        match load_one(config, plugin, lib.as_ref()) {
            Ok(plugin) => {
                loaded.capabilities |= plugin.capabilities;
                loaded.list.push(plugin);
            }
            Err(failure) => {
                warn!("skipping plugin \"{}\": {}", plugin.name, failure.reason);
                if failure.required && required_failure.is_none() {
                    required_failure = Some(Error::Required {
                        name: plugin.name.clone(),
                        reason: failure.reason,
                    });
                }
            }
        }
    }

    let _ = PLUGINS.set(loaded);

    match required_failure {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

fn load_one(
    config: &Config,
    plugin: &PluginConfig,
    lib: Option<&'static Library>,
) -> Result<LoadedPlugin, LoadFailure> {
    let fail = |reason: String, required: bool| LoadFailure {
        reason,
        required: plugin.required || required,
    };

    let now = Instant::now();
    let lib = lib.ok_or_else(|| fail("shared library could not be opened".into(), false))?;
    let plugin_lib = PluginVtable::load(lib)
        .ok_or_else(|| fail("its vtable could not be loaded".into(), false))?;

    // Check plugin api version (compare major.minor only)
    let plugin_api_version = plugin_lib.pgdog_plugin_api_version();
    if !same_major_minor(&plugin_api_version, pgdog_plugin::VERSION) {
        return Err(fail(
            format!(
                "it was compiled with a different plugin API version ({})",
                &*plugin_api_version
            ),
            false,
        ));
    }

    // Check Rust compiler version.
    let plugin_rustc_version = plugin_lib.rustc_version();
    if pgdog_plugin::RUSTC_VERSION != &*plugin_rustc_version {
        return Err(fail(
            format!(
                "it was compiled with a different compiler version ({})",
                &*plugin_rustc_version
            ),
            false,
        ));
    }

    // Safe to read past the version fields now that versions match.
    let capabilities = plugin_lib.capabilities();
    let required = capabilities.contains(Capabilities::REQUIRED);

    let plugin_config_path = plugin
        .config
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_default();

    let pd_config = PdConfig {
        log_level: PdStr::from(config.general.log_level.as_str()),
        log_json: matches!(
            config.general.log_format,
            LogFormat::Json | LogFormat::JsonFlattened
        ),
        plugin_config: PdStr::from(plugin_config_path.as_str()),
    };

    plugin_lib.logging_init(pd_config);

    plugin_lib.init();
    debug!("plugin \"{}\" initialized", plugin.name);

    if !plugin_lib.config(pd_config) {
        return Err(fail("it failed to load its configuration".into(), required));
    }

    info!(
        "loaded \"{}\" plugin (v{}) [{:.4}ms]",
        plugin.name,
        &*plugin_lib.plugin_version(),
        now.elapsed().as_secs_f64() * 1000.0
    );

    Ok(LoadedPlugin {
        name: plugin.name.to_owned(),
        vtable: plugin_lib,
        capabilities,
    })
}

/// Shutdown plugins.
pub(crate) fn shutdown() {
    for plugin in plugins() {
        plugin.vtable.fini();
    }
}

/// Get all loaded plugins, in config order.
pub(crate) fn plugins() -> &'static [LoadedPlugin] {
    PLUGINS
        .get()
        .map(|plugins| plugins.list.as_slice())
        .unwrap_or_default()
}

/// Loaded plugins that implement the given hook, in config order.
pub(crate) fn with_capability(
    capability: Capabilities,
) -> impl Iterator<Item = &'static LoadedPlugin> {
    plugins()
        .iter()
        .filter(move |plugin| plugin.has(capability))
}

/// At least one loaded plugin implements the given hook.
pub(crate) fn has_capability(capability: Capabilities) -> bool {
    PLUGINS
        .get()
        .is_some_and(|plugins| plugins.capabilities.contains(capability))
}

/// Send a freshly loaded schema to plugins that asked for it.
pub(crate) fn schema_loaded(database: &str, schema: &Schema) {
    if !has_capability(Capabilities::SCHEMA) {
        return;
    }

    let snapshot = match serde_json::to_string(&**schema) {
        Ok(snapshot) => snapshot,
        Err(err) => {
            error!("failed to serialize schema for plugins: {err}");
            return;
        }
    };
    let epoch = SCHEMA_EPOCH.fetch_add(1, Ordering::Relaxed) + 1;

    for plugin in with_capability(Capabilities::SCHEMA) {
        plugin.vtable.schema(database, epoch, &snapshot);
        debug!(
            "sent schema for \"{}\" to plugin \"{}\" [epoch: {}]",
            database, plugin.name, epoch
        );
    }
}

/// Ask plugins to reload their configuration.
pub(crate) fn reload() {
    for plugin in plugins() {
        if !plugin.vtable.reload() {
            warn!(
                "plugin \"{}\" failed to reload its configuration, keeping the previous one",
                plugin.name
            );
        }
    }
}

/// Load plugins from config.
pub(crate) fn load_from_config() -> Result<(), Error> {
    let config = crate::config::config();

    load(&config.config)
}

#[cfg(test)]
pub(crate) mod test;
