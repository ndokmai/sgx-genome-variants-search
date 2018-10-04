#! /bin/bash

#----------------------------------------------------------------------------
# Parse our settings file
#----------------------------------------------------------------------------

source settings

# Optional settings

if [ "$QUERY_IAS_PRODUCTION" != "" -a "$QUERY_IAS_PRODUCTION" -ne 0 ]; then
	sp_production=-P
fi

if [ "$LINKABLE" != "" -a "$LINKABLE" -ne 0 ]; then
	flag_linkable=-l
fi

# Optional client settings

if [ "$RANDOM_NONCE" != "" -a "$RANDOM_NONCE" -ne 0 ]; then
	cl_nonce=-r
fi

if [ "$USE_PLATFORM_SERVICES" != "" -a "$USE_PLATFORM_SERVICES" -ne 0 ]; then
	cl_pse=-m
fi

# Optional service provider/server settings

if [ "$IAS_CLIENT_KEY_FILE" != "" ]; then
	sp_cert_key="--ias-cert-key=$IAS_CLIENT_KEY_FILE"
fi

if [ "$IAS_CLIENT_CERT_KEY_PASSWORD_FILE" != "" ]; then
	sp_cert_passwd="--ias-cert-passwd=$IAS_CLIENT_CERT_KEY_PASSWORD_FILE"
fi

if [ "$IAS_CLIENT_CERT_TYPE" != "" ]; then
	sp_cert_type="--ias-cert-type=$IAS_CLIENT_CERT_TYPE"
fi

if [ "$IAS_PROXY_URL" != "" ]; then
	sp_proxy="--proxy=$IAS_PROXY_URL"
fi

if [ "$IAS_DISABLE_PROXY" != "" -a "$IAS_DISABLE_PROXY" -ne 0 ]; then
	sp_noproxy="-x"
fi

# Debugging options

if [ "$VERBOSE" != "" -a "$VERBOSE" -ne 0 ]; then
	flag_verbose=-v
fi

if [ "$DEBUG" != "" -a "$DEBUG" -ne 0 ]; then
	flag_debug=-d
fi

#----------------------------------------------------------------------------
# Output
#----------------------------------------------------------------------------

output="-s $SPID \
    -A $IAS_REPORT_SIGNING_CA_FILE \
    -C $IAS_CLIENT_CERT_FILE \
    $sp_cert_key $sp_noproxy $sp_proxy $sp_cert_passwd $sp_cert_type \
    $flag_linkable $flag_debug $flag_verbose \
    $sp_production"

echo $output > _args_
