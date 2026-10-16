# frozen_string_literal: true

require 'pg'
require 'rspec'

# Statement, mask and error hooks of test-plugin-compatible, loaded as a shared library.
describe 'statement, mask and error hooks' do
  let(:conn) { PG.connect('postgres://pgdog:pgdog@127.0.0.1:6432/pgdog') }

  after { conn.close }

  describe 'rewrite' do
    it 'rewrites simple queries' do
      result = conn.exec("SELECT 'pgdog_plugin_rewrite' AS v")
      expect(result[0]['v']).to eq('pgdog_plugin_rewritten')
    end

    it 'rewrites extended protocol queries' do
      result = conn.exec_params("SELECT 'pgdog_plugin_rewrite' AS v, $1::int AS n", [7])
      expect(result[0]['v']).to eq('pgdog_plugin_rewritten')
      expect(result[0]['n']).to eq('7')
    end

    it 'rewrites prepared statements' do
      conn.prepare('rewrite', "SELECT 'pgdog_plugin_rewrite' AS v, $1::int AS n")
      3.times do |i|
        result = conn.exec_prepared('rewrite', [i])
        expect(result[0]['v']).to eq('pgdog_plugin_rewritten')
        expect(result[0]['n']).to eq(i.to_s)
      end
    end
  end

  describe 'block' do
    it 'blocks simple queries' do
      expect { conn.exec("SELECT 'pgdog_plugin_block'") }
        .to raise_error(PG::InsufficientPrivilege, /blocked by test plugin for pgdog/)

      # The connection is still usable.
      expect(conn.exec('SELECT 1 AS one')[0]['one']).to eq('1')
    end

    it 'blocks extended protocol queries' do
      expect { conn.exec_params("SELECT 'pgdog_plugin_block', $1::int", [1]) }
        .to raise_error(PG::InsufficientPrivilege)
      expect { conn.prepare('blocked', "SELECT 'pgdog_plugin_block'") }
        .to raise_error(PG::InsufficientPrivilege)

      expect(conn.exec_params('SELECT $1::int AS n', [2])[0]['n']).to eq('2')
    end

    it 'aborts the transaction' do
      conn.exec('BEGIN')
      expect { conn.exec("SELECT 'pgdog_plugin_block'") }
        .to raise_error(PG::InsufficientPrivilege)
      expect(conn.transaction_status).to eq(PG::PQTRANS_INERROR)
      expect { conn.exec('SELECT 1') }.to raise_error(PG::InFailedSqlTransaction)

      result = conn.exec('COMMIT')
      expect(result.cmd_status).to eq('ROLLBACK')
      expect(conn.transaction_status).to eq(PG::PQTRANS_IDLE)
    end
  end

  describe 'mask' do
    let(:sql) { "SELECT 'secret' AS v, NULL::text AS n, 42 AS i /* pgdog_plugin_uppercase */" }

    it 'masks simple query rows' do
      row = conn.exec(sql)[0]
      expect(row).to eq('v' => 'SECRET', 'n' => nil, 'i' => '42')
    end

    it 'masks rows of prepared statements' do
      conn.prepare('mask', sql)
      3.times do
        expect(conn.exec_prepared('mask')[0]['v']).to eq('SECRET')
      end
    end

    it 'masks text columns requested in binary' do
      # Text and binary formats of text are the same bytes.
      result = conn.exec_params("SELECT 'secret'::text AS v /* pgdog_plugin_uppercase */", [], 1)
      expect(result[0]['v']).to eq('SECRET')
    end

    it 'masks large results in order' do
      result = conn.exec("SELECT 'row ' || n FROM generate_series(1, 5000) n /* pgdog_plugin_uppercase */")
      expect(result.column_values(0)).to eq((1..5000).map { |n| "ROW #{n}" })
    end

    it 'only masks the statements it was asked to' do
      expect(conn.exec("SELECT 'secret' AS v")[0]['v']).to eq('secret')
    end
  end

  describe 'errors' do
    it 'redacts errors from Postgres' do
      expect { conn.exec("SELECT 'pgdog_plugin_secret'::int") }
        .to raise_error(PG::InvalidTextRepresentation) { |error|
          # libpq quotes the client's own SQL in the message; check what the server sent.
          primary = error.result.error_field(PG::PG_DIAG_MESSAGE_PRIMARY)
          expect(primary).not_to include('pgdog_plugin_secret')
          expect(primary).to include('[redacted]')
        }
    end
  end
end
