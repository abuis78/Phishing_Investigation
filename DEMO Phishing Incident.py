"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'set_status_1' block
    set_status_1(container=container)

    return

@phantom.playbook_block()
def playbook_sender_analysis_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_sender_analysis_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "Phishing_Investigation/sender_analysis", returns the playbook_run_id
    playbook_run_id = phantom.playbook("Phishing_Investigation/sender_analysis", container=container, name="playbook_sender_analysis_1", callback=playbook_email_subject_analysis_1)

    return


@phantom.playbook_block()
def playbook_email_subject_analysis_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_email_subject_analysis_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "Phishing_Investigation/email subject analysis", returns the playbook_run_id
    playbook_run_id = phantom.playbook("Phishing_Investigation/email subject analysis", container=container, name="playbook_email_subject_analysis_1", callback=playbook_url_analysis_1)

    return


@phantom.playbook_block()
def playbook_url_analysis_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_url_analysis_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "Phishing_Investigation/URL analysis", returns the playbook_run_id
    playbook_run_id = phantom.playbook("Phishing_Investigation/URL analysis", container=container, name="playbook_url_analysis_1", callback=playbook_domain_analysis_1)

    return


@phantom.playbook_block()
def playbook_inform_user___in_progress_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_inform_user___in_progress_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "Phishing_Investigation/Inform user - in progress", returns the playbook_run_id
    playbook_run_id = phantom.playbook("Phishing_Investigation/Inform user - in progress", container=container, name="playbook_inform_user___in_progress_1", callback=playbook_sender_analysis_1)

    return


@phantom.playbook_block()
def set_status_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_status_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_status(container=container, status="in progress")

    container = phantom.get_container(container.get('id', None))

    promote_to_case_2(container=container)

    return


@phantom.playbook_block()
def promote_to_case_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("promote_to_case_2() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.promote(container=container, template="Phishing Incident")

    container = phantom.get_container(container.get('id', None))

    playbook_inform_user___in_progress_1(container=container)

    return


@phantom.playbook_block()
def playbook_domain_analysis_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_domain_analysis_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "Phishing_Investigation/domain analysis", returns the playbook_run_id
    playbook_run_id = phantom.playbook("Phishing_Investigation/domain analysis", container=container, name="playbook_domain_analysis_1", callback=playbook_file_analysis_1)

    return


@phantom.playbook_block()
def playbook_manual_steps___classification_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_manual_steps___classification_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "Phishing_Investigation/manual steps - classification", returns the playbook_run_id
    playbook_run_id = phantom.playbook("Phishing_Investigation/manual steps - classification", container=container, name="playbook_manual_steps___classification_1")

    return


@phantom.playbook_block()
def playbook_file_analysis_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbook_file_analysis_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "Phishing_Investigation/file analysis", returns the playbook_run_id
    playbook_run_id = phantom.playbook("Phishing_Investigation/file analysis", container=container, name="playbook_file_analysis_1", callback=playbook_manual_steps___classification_1)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

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

    return