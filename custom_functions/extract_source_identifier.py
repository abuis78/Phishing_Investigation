def extract_source_identifier(email_subject=None, email_body=None, source_identifier_prefix=None, **kwargs):
    """
    Args:
        email_subject
        email_body
        source_identifier_prefix
    
    Returns a JSON-serializable object that implements the configured data paths:
        source_identifier
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import re    
    
    outputs = {}
    
    # Write your custom code here...
    phantom.debug(email_body)
    pattern = re.compile("\[PMI:(.*?)\]")
    phantom.debug(pattern)
    result = pattern.search(email_body)
    
    if result:
        outputs["source_identifier"] = result.group(1)
        #outputs["source_identifier"] = True
        phantom.debug(result.group(1))
    else:
        outputs["source_identifier"] = False

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
