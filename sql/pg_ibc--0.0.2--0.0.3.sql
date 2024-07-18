CREATE OR REPLACE FUNCTION "decode_transfer_packet"(input bytea, rpc_type text, throws boolean, extension_format text) RETURNS jsonb
STRICT IMMUTABLE PARALLEL SAFE
LANGUAGE c 
AS '$libdir/pg_ibc-0.0.3', 'decode_transfer_packet_wrapper';