def source_identifier_decode(source_identifier=None, **kwargs):
    """
    Args:
        source_identifier
    
    Returns a JSON-serializable object that implements the configured data paths:
        container_id
        pattern_1
        pattern_2
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import base64    
    
    outputs = {}
    
    # Write your custom code here...
    phantom.debug(source_identifier)
    phantom.debug(type(source_identifier))
    decoded = base64.b64decode(source_identifier).decode()
    info = decoded.split("|")
    
    phantom.debug(info)
    outputs["container_id"] = info[0]
    outputs["pattern_1"] = info[1]
    outputs["pattern_2"] = info[2]
    phantom.debug('Container-ID decoded: container_id {}'.format(info[0]))    
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
