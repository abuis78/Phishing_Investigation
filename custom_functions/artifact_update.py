def artifact_update(artifact_id=None, name=None, description=None, label=None, severity=None, cef_field=None, cef_value=None, cef_data_type=None, tags=None, input_json=None, **kwargs):
    """
    Update an artifact with the specified attributes. All parameters are optional, except that cef_field and cef_value must both be provided if one is provided. Supports all fields available in /rest/artifact. Add any unlisted inputs as dictionary keys in input_json. Unsupported keys will automatically be dropped.
    
    Args:
        artifact_id (CEF type: phantom artifact id): ID of the artifact to update, which is required.
        name: Change the name of the artifact.
        description: Change the description of the artifact
        label: Change the label of the artifact.
        severity: Change the severity of the artifact. Typically this is either "High", "Medium", or "Low".
        cef_field: The name of the CEF field to populate in the artifact, such as "destinationAddress" or "sourceDnsDomain". Required only if cef_value is provided.
        cef_value (CEF type: *): The value of the CEF field to populate in the artifact, such as the IP address, domain name, or file hash. Required only if cef_field is provided.
        cef_data_type: The CEF data type of the data in cef_value. For example, this could be "ip", "hash", or "domain". Optional, but only operational if cef_field is provided.
        tags: A comma-separated list of tags to apply to the artifact, which is optional.
        input_json: Optional parameter to modify any extra attributes of the artifact. Input_json will be merged with other inputs. In the event of a conflict, input_json will take precedence.
    
    Returns a JSON-serializable object that implements the configured data paths:
        
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    json_dict = None
    valid_keys = [
        'artifact_type', 'cef', 'cef_data', 'cef_types', 'container', 'container_id',  
        'field_mapping', 'data', 'description', 'end_time', 'has_note', 'identifier', 
        'ingest_app', 'ingest_app_id', 'kill_chain', 'label', 'name', 'owner_id', 
        'parent_container', 'parent_artifact', 'raw_data', 'run_automation', 'severity',
        'source_data_identifier', 'start_time', 'tags', 'type'
    ]
    if not isinstance(artifact_id, int):
        raise TypeError("artifact_id is required")
    
    rest_artifact = phantom.build_phantom_rest_url('artifact', artifact_id)
    updated_artifact = phantom.requests.get(rest_artifact, verify=False).json()
    if updated_artifact.get('failed'):
        raise RuntimeError(f"GET /rest/artifact/{artifact_id} failed, {updated_artifact.get('message')}")
        
    if name:
        updated_artifact['name'] = name
    if label:
        updated_artifact['label'] = label
    if severity:
        updated_artifact['severity'] = severity 
    if tags:
        updated_artifact['tags'].append(tags.replace(" ", "").split(","))
        updated_artifact['tags'] = list(set(updated_artifact['tags']))
    if description:
        updated_artifact['description'] = description

    # validate that if cef_field or cef_value is provided, the other is also provided
    if (cef_field and not cef_value) or (cef_value and not cef_field):
        raise ValueError("only one of cef_field and cef_value was provided")

    # cef_data should be formatted {cef_field: cef_value}
    if cef_field:
        updated_artifact['cef'].update({cef_field: cef_value})
        if cef_data_type and isinstance(cef_data_type, str):
            updated_artifact['cef_types'].update({cef_field: [cef_data_type]})
    
    if input_json:
        # ensure valid input_json
        if isinstance(input_json, dict):
            json_dict = input_json
        elif isinstance(input_json, str):
            json_dict = json.loads(input_json)
        else:
            raise ValueError("input_json must be either 'dict' or valid json 'string'")
            
    if json_dict:
        # Merge dictionaries, using the value from json_dict if there are any conflicting keys
        for json_key in json_dict:
            if json_key in valid_keys:
                # translate keys supported in phantom.add_artifact() to their corresponding values in /rest/artifact
                if json_key == 'container':
                    updated_artifact['container_id'] = json_dict[json_key]
                elif json_key == 'raw_data':
                    updated_artifact['data'].update(json_dict[json_key])
                elif json_key == 'cef_data':
                    updated_artifact['cef'].update(json_dict[json_key])
                elif json_key == 'identifier':
                    updated_artifact['source_data_identifier'] = json_dict[json_key]
                elif json_key == 'ingest_app':
                    updated_artifact['ingest_app_id'] = json_dict[json_key]
                elif json_key == 'artifact_type':
                    updated_artifact['type'] = json_dict[json_key]
                elif json_key == 'field_mapping':
                    updated_artifact['cef_types'].update(json_dict[json_key])
                else:
                    if isinstance(updated_artifact[json_key], dict):
                        updated_artifact[json_key].update(json_dict[json_key])
                    elif isinstance(updated_artifact[json_key], list):
                        updated_artifact[json_key].append(json_dict[json_key])
                        updated_artifact[json_key] = list(set(updated_artifact[json_key]))
                    else:
                        updated_artifact[json_key] = json_dict[json_key]
            else:
                phantom.debug(f"Unsupported key: '{json_key}'")
    
    # now actually update the artifact
    phantom.debug('Updating artifact {} with the following attributes:\n{}'.format(artifact_id, updated_artifact))
    response_json = phantom.requests.post(rest_artifact, json=updated_artifact, verify=False).json()
    if not response_json.get('success'):
        raise RuntimeError("POST /rest/artifact failed")
    else:
        outputs['artifact_id'] = response_json['id']

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
