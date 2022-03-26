"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'detect_language' block
    detect_language(container=container)

    return

def detect_language(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("detect_language() called")

    input_parameter_0 = "text_string"

    detect_language__language = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    phantom.debug("---------")
    u = 'https://google-translate1.p.rapidapi.com/language/translate/v2/detect'
    headers =  {
        'content-type': 'application/x-www-form-urlencoded',
        'Accept-Encoding': 'application/gzip',
        'X-RapidAPI-Host': 'google-translate1.p.rapidapi.com',
        'X-RapidAPI-Key': '44aaaeef79msh75169124fb09b39p153dedjsnab8c1122a6a5'
      }
    
    payload = "q=English is hard, but detectably so"
    
    response = phantom.requests.post(
        u,
        data=payload, 
        headers=headers,
        verify=False,
    )

    phantom.debug("phantom returned status with message {}".format(response.text))
    
    detect_language__language = response.json()
    phantom.debug(detect_language__language["data"]["detections"][0])
    
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="detect_language:language", value=json.dumps(detect_language__language))

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    output = {
        "text_translation": "",
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return