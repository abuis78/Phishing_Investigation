def define_source_identifier(container_id=None, pattern_1=None, pattern_2=None, source_identifier_prefix=None, **kwargs):
    """
    Args:
        container_id
        pattern_1
        pattern_2
        source_identifier_prefix
    
    Returns a JSON-serializable object that implements the configured data paths:
        source_identifier_key
        source_identifier_prefix_key
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import base64    
    
    outputs = {}
    
    # Write your custom code here...
    outputs["source_identifier_key"] = base64.b64encode("{}|{}|{}".format(container_id, pattern_1, pattern_2).encode()).decode()
    phantom.debug(outputs["source_identifier_key"])
    outputs["source_identifier_prefix_key"] = "[{}: {}]".format(source_identifier_prefix, outputs["source_identifier_key"])
    phantom.debug(outputs["source_identifier_prefix_key"])
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
