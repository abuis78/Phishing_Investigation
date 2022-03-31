def add_email_to_corresponding_contaiiner(container_id=None, subject=None, body=None, **kwargs):
    """
    Adding email as note to the corresponding container
    
    Args:
        container_id
        subject
        body
    
    Returns a JSON-serializable object that implements the configured data paths:
        success
        message
        note_id
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    success, message, note_id = phantom.add_note(container=container_id, note_format='markdown', note_type='general', title=subject, content=body)
    
    outputs["success"] = success
    outputs["message"] = message
    outputs["note_id"] = note_id
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
