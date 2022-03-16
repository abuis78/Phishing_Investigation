def container_list_various_conditions(filter_condition=None, time_span=None, container_id=None, **kwargs):
    """
    Collecting of existing containers on the basis of different parameters. To create a list of container ID from them. Here time plays a role. e.g. show me all containers <filter> that are not older than x hours.
    
    Args:
        filter_condition: example: _filter_status="new"&_filter_label="phishing-mailbox
        time_span
        container_id
    
    Returns a JSON-serializable object that implements the configured data paths:
        container_id_list
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    from datetime import datetime, timedelta
    
    outputs = {}
    
    # Write your custom code here...
    u1 = phantom.build_phantom_rest_url('container',container_id)
    r1 = phantom.requests.get(u1,verify=False)  
    c1 = r1.json()
    t1 = datetime.strptime(c1["create_time"], "%Y-%m-%dT%H:%M:%S.%fZ")
    phantom.debug(t1)
    
    u2 = phantom.build_phantom_rest_url('container') + '?' + filter_condition
    r2= phantom.requests.get(u2,verify=False)    
    container_data = r2.json()["data"]
    #filterd_list = [ c["id"] for c in container_data if c["status"] == "new" and c["label"] == "phishing-mailbox"
    
    filterd_list = []
    for c in container_data:
        t2 = datetime.strptime(c["create_time"], "%Y-%m-%dT%H:%M:%S.%fZ")
        diff = t1 - t2
        phantom.debug(diff)
        if diff > timedelta(hours=time_span):
            id_list = c["id"]
            filterd_list.append(id_list)
            
    phantom.debug(filterd_list)
    outputs["container_id_list"] = filterd_list
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
