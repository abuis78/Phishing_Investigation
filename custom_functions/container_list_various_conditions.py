def container_list_various_conditions(filter_condition=None, time_span=None, current_time=None, **kwargs):
    """
    Collecting of existing containers on the basis of different parameters. To create a list of container ID from them. Here time plays a role. e.g. show me all containers <filter> that are not older than x hours.
    
    Args:
        filter_condition: example: _filter_status="new"&_filter_label="phishing-mailbox
        time_span
        current_time
    
    Returns a JSON-serializable object that implements the configured data paths:
        container_id_list
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    from datetime import datetime, timedelta
    
    outputs = {}
    
    # Write your custom code here...
    u = phantom.build_phantom_rest_url('container') + '?' + filter_condition
    response = phantom.requests.get(u,verify=False)    
    container_data = response.json()["data"]
    #filterd_list = [ c["id"] for c in container_data if c["status"] == "new" and c["label"] == "phishing-mailbox"
    
    filterd_list = []
    for c in container_data:
        create_time = datetime.strptime(c["create_time"], "%Y-%m-%dT%H:%M:%S.%fZ")
        phantom.debug(create_time)
        current_time = datetime.strptime(current_time, "%Y-%m-%dT%H:%M:%S.%fZ")
        phantom.debug(current_time)
        id_list = c["id"]
        filterd_list.append(id_list)
            
    phantom.debug(filterd_list)
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
