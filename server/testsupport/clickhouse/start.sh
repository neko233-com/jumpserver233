#!/bin/sh
set -eu
mkdir -p /run/qa-tls /etc/clickhouse-server/config.d
cp /qa-input/server.crt /run/qa-tls/server.crt
cp /qa-input/server.key /run/qa-tls/server.key
chmod 600 /run/qa-tls/server.key
cat >/run/qa-tls/client.xml <<'EOF'
<config><user>qadb</user><password>synthetic-clickhouse-query-233</password></config>
EOF
chmod 600 /run/qa-tls/client.xml
chown -R clickhouse:clickhouse /run/qa-tls
cat >/etc/clickhouse-server/config.d/jms233-qa.xml <<'EOF'
<clickhouse>
 <https_port>8443</https_port>
 <openSSL><server><certificateFile>/run/qa-tls/server.crt</certificateFile><privateKeyFile>/run/qa-tls/server.key</privateKeyFile><disableProtocols>sslv2,sslv3,tlsv1,tlsv1_1</disableProtocols></server></openSSL>
 <query_log remove="1"/><query_thread_log remove="1"/><trace_log remove="1"/><metric_log remove="1"/><asynchronous_metric_log remove="1"/><part_log remove="1"/><text_log remove="1"/><processors_profile_log remove="1"/><query_views_log remove="1"/>
 <max_server_memory_usage>536870912</max_server_memory_usage>
 <background_schedule_pool_size>2</background_schedule_pool_size>
 <background_pool_size>4</background_pool_size>
 <background_merges_mutations_concurrency_ratio>8</background_merges_mutations_concurrency_ratio>
 <background_fetches_pool_size>2</background_fetches_pool_size>
 <background_move_pool_size>1</background_move_pool_size>
 <background_common_pool_size>1</background_common_pool_size>
 <background_buffer_flush_schedule_pool_size>1</background_buffer_flush_schedule_pool_size>
 <background_distributed_schedule_pool_size>1</background_distributed_schedule_pool_size>
 <background_message_broker_schedule_pool_size>1</background_message_broker_schedule_pool_size>
 <max_thread_pool_size>512</max_thread_pool_size>
</clickhouse>
EOF
cat >/etc/clickhouse-server/users.d/jms233-qa.xml <<'EOF'
<clickhouse><profiles><default><max_threads>2</max_threads><max_insert_threads>1</max_insert_threads></default></profiles></clickhouse>
EOF
exec /entrypoint.sh "$@"
