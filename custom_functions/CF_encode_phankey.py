def CF_encode_phankey(container_id=None, user_email=None, **kwargs):
    """
    Creates a new PHANKEY
    
    Args:
        container_id
        user_email
    
    Returns a JSON-serializable object that implements the configured data paths:
        PHANKEY (CEF type: *): Encoded PHANKEY
        PHANKEY_subject: PHANKEY formatted for email subject
        PHANKEY_body
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import base64
    
    outputs = {}
    
    outputs["PHANKEY"] = base64.b64encode("{}|{}".format(container_id, user_email).encode()).decode()
    phantom.debug(outputs["PHANKEY"])
    outputs["PHANKEY_subject"] = "[{}]".format(outputs["PHANKEY"])
    outputs["PHANKEY_body"] = "[source-identifier:{}]".format(outputs["PHANKEY"])

    # Write your custom code here...
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
