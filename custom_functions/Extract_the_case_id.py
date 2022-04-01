def Extract_the_case_id(subject=None, **kwargs):
    """
    This CF extracts the case ID from the subject. It is returned in the subject after the following combination "[1234]" ... the case id is returned to use this for further processing.
    
    Args:
        subject
    
    Returns a JSON-serializable object that implements the configured data paths:
        case_id
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import re    
    
    outputs = {}
    
    phantom.debug(subject)
    pattern = re.compile("\[(.*?)\]")
    phantom.debug(pattern)
    result = pattern.search(subject)
    
    if result:
        outputs["case_id"] = result.group(1)
        #outputs["source_identifier"] = True
        phantom.debug(result.group(1))
    else:
        outputs["case_id"] = False    
    
    # Write your custom code here...
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
