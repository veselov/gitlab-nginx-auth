function encoded_request_uri(r) {
    return encodeURIComponent(r.variables['request_uri']);
}
export default { encoded_request_uri }

