# To change this license header, choose License Headers in Project Properties.
# To change this template file, choose Tools | Templates
# and open the template in the editor.
import base64
import configparser
import hashlib
import json
import logging
import os
import sys
import tempfile
import time
import traceback
from threading import Thread
from time import sleep

import pika
import yaml

from cryptography.fernet import Fernet

from service.awx_service import AWXService
from service.deploy_service import DeployService
from service.tosca_helper import ToscaHelper

logger = logging.getLogger(__name__)

done = False


# if not getattr(logger, 'handler_set', None):
# logger.setLevel(logging.INFO)
# h = logging.StreamHandler()
# formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# h.setFormatter(formatter)
# logger.addHandler(h)
# logger.handler_set = True


def init_channel(rabbitmq_host, queue_name):
    connection = pika.BlockingConnection(pika.ConnectionParameters(host=rabbitmq_host))
    channel = connection.channel()
    channel.queue_declare(queue=queue_name)
    return channel, connection


def start(this_channel):
    try:
        this_channel.basic_qos(prefetch_count=1)
        this_channel.basic_consume(queue=queue_name, on_message_callback=on_request)
        logger.info(" [x] Awaiting RPC requests")
        this_channel.start_consuming()
    except:
        exit(-1)


def on_request(ch, method, props, body):
    response = handle_delivery(body)

    ch.basic_publish(exchange='',
                     routing_key=props.reply_to,
                     properties=pika.BasicProperties(correlation_id=
                                                     props.correlation_id),
                     body=str(response))
    ch.basic_ack(delivery_tag=method.delivery_tag)



def save_tosca_template(tosca_template_dict):
    tmp_path = tempfile.mkdtemp()
    tosca_template_path = tmp_path + os.path.sep + 'toscaTemplate.yml'
    logger.info('Saving tosca_template at: '+tosca_template_path)
    with open(tosca_template_path, 'w') as outfile:
        yaml.dump(tosca_template_dict, outfile, default_flow_style=False)
    return  tosca_template_path


# def semaphore(tosca_template_path=None, tosca_template_dict=None):
#     logger.info('Deploying using semaphore.')
#     tosca_helper = ToscaHelper(sure_tosca_base_url, tosca_template_path)
#     # nodes = tosca_helper.get_application_nodes()
#     nodes = tosca_helper.get_deployment_node_pipeline()
#
#     deployService = DeployService(semaphore_base_url=semaphore_base_url, semaphore_username=semaphore_username,
#                                   semaphore_password=semaphore_password, vms=tosca_helper.get_vms())
#     try:
#         for node in nodes:
#             updated_node = deployService.deploy(node)
#             if isinstance(updated_node, list):
#                 for node in updated_node:
#                     tosca_template_dict = tosca_helper.set_node(node, tosca_template_dict)
#                     # logger.info("tosca_template_dict :" + json.dumps(tosca_template_dict))
#             else:
#                 tosca_template_dict = tosca_helper.set_node(updated_node, tosca_template_dict)
#                 # logger.info("tosca_template_dict :" + json.dumps(tosca_template_dict))
#
#         response = {'toscaTemplate': tosca_template_dict}
#         output_current_milli_time = int(round(time.time() * 1000))
#         response["creationDate"] = output_current_milli_time
#         logger.info("Returning Deployment")
#         logger.info("Output message:" + json.dumps(response))
#         return json.dumps(response)
#     except Exception as e:
#         track = traceback.format_exc()
#         print(track)
#         raise


def execute_workflows(workflows=None, topology_template_workflow_steps=None, awx=None):
    launched_ids = []
    attributes = {}
    tosca_template_dict = {}
    for workflow_name in workflows:
        workflow = workflows[workflow_name]
        description = None
        if 'description' in workflow:
            description = workflow['description']
        wf_ids = awx.create_workflow(description=description, workflow_name=workflow_name)
        logger.info('Created workflow with ID: ' + str(wf_ids[0]))
        workflow_node_ids = awx.create_dag(workflow_id=wf_ids[0],
                                           tosca_workflow=workflow,
                                           topology_template_workflow_steps=topology_template_workflow_steps)
        logger.info('Added nodes to workflow')
        for wf_id in wf_ids:
            wf_job_ids = awx.launch(wf_id)
            logger.info('Launch workflows: ' + str(wf_job_ids))
            launched_ids += wf_job_ids
        for launched_id in launched_ids:
            while awx.get_job_status(launched_id) == 'running':
                logger.info('Workflow: ' + str(launched_id) + ' status: ' + awx.get_job_status(launched_id))
                sleep(5)
            job_id = awx.get_attribute_job_id(launched_id)
            if not job_id:
                raise Exception('Could not find attribute job id from workflow: ' + str(launched_id))

            attributes.update(awx.get_job_artefacts(job_id))
            logger.info('Updated attributes:' + str(attributes))

        tosca_template_dict = awx.set_tosca_node_attributes(tosca_template_dict, attributes)
    return tosca_template_dict


def awx(tosca_template_path=None, tosca_template_dict=None):
    try:
        tosca_service_is_up = ToscaHelper.service_is_up(sure_tosca_base_url)
        logger.info('Deploying using awx.')

        if tosca_service_is_up:
            tosca_helper = ToscaHelper(sure_tosca_base_url, tosca_template_path)
            node_templates = tosca_template_dict['topology_template']['node_templates']

            awx = AWXService(api_url=awx_base_url, username=awx_username, password=awx_password,
                             tosca_helper=tosca_helper)
            organization_id = awx.create_organization('sdia')
            topology_template_workflow_steps = {}
            for tosca_node_name in node_templates:
                tosca_node = node_templates[tosca_node_name]
                logger.info('Resolving function values for: ' + tosca_node_name)
                tosca_node = tosca_helper.resolve_function_values(tosca_node)

                credential = None
                if 'attributes' in tosca_node:
                    if 'credential' in tosca_node['attributes']:
                        credential = tosca_node['attributes']['credential']
                    if 'user_key_pair' in tosca_node['attributes']:
                        credential = tosca_node['attributes']['user_key_pair']
                if 'properties' in tosca_node:
                    if 'credential' in tosca_node['properties']:
                        credential = tosca_node['properties']['credential']
                    if 'user_key_pair' in tosca_node['properties']:
                        credential = tosca_node['properties']['user_key_pair']

                logger.info('Creating workflow steps for: ' + tosca_node_name)
                node_workflow_steps = awx.create_workflow_steps(tosca_node, organization_id=organization_id,
                                                                credential=credential)
                topology_template_workflow_steps.update(node_workflow_steps)

            workflows = tosca_helper.get_workflows()
            if workflows:
                tosca_template_dict = execute_workflows(workflows=workflows,
                                                             topology_template_workflow_steps=topology_template_workflow_steps,
                                                             awx=awx)
    except (Exception) as ex:
        track = traceback.format_exc()
        print(track)
        raise

    response = {'toscaTemplate': tosca_template_dict}
    logger.info("Returning Deployment")
    logger.info("Output message:" + json.dumps(response))
    return json.dumps(response)

def decode_credentials(tosca_template_dict):
    logger.info('Decoding credentials.')
    node_templates = tosca_template_dict['topology_template']['node_templates']
    enc_key = bytes(secret, 'utf-8')
    for node_template_name in node_templates:
        node_template = node_templates[node_template_name]
        if 'attributes' in node_template and 'credentials' in node_template['attributes']:
            credentials = node_template['attributes']['credentials']
            for credential in credentials:
                if 'token' in credential:
                    token = credential['token']
                    credential['token'] = decode(token,enc_key)
                if 'keys' in credential:
                    keys = credential['keys']
                    for key_name in keys:
                        token = keys[key_name]
                        keys[key_name] = decode(token, enc_key)
    return tosca_template_dict


def decode(contents,key):
    try:
        fernet = Fernet(key)
        dec = fernet.decrypt(contents.encode()).decode()
        return dec
    except Exception as ex:
        done = True
        e = sys.exc_info()[0]
        logger.info("Error: " + str(e))
        print(e)
        exit(-1)





def handle_delivery(message):
    logger.info("Got: " + str(message))
    try:
        message = message.decode()
    except (UnicodeDecodeError, AttributeError):
        pass
    parsed_json_message = json.loads(message)
    owner = parsed_json_message['owner']
    tosca_file_name = 'tosca_template'
    tosca_template_dict = parsed_json_message['toscaTemplate']
    tosca_template_dict = decode_credentials(tosca_template_dict)

    tosca_template_path = save_tosca_template(tosca_template_dict)
    # if 'workflows' in tosca_template_dict['topology_template']:
    return awx(tosca_template_dict=tosca_template_dict, tosca_template_path=tosca_template_path)

    # return semaphore(tosca_template_dict=tosca_template_dict, tosca_template_path=tosca_template_path)


def threaded_function(args):
    while not done:
        connection.process_data_events()
        sleep(8)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    global channel, queue_name, connection, rabbitmq_host, sure_tosca_base_url,semaphore_base_url, semaphore_username, \
        semaphore_password, awx_base_url, awx_username, awx_password, secret

    config = configparser.ConfigParser()
    config.read('properties.ini')
    sure_tosca_base_url = config['tosca-sure']['base_url']
    semaphore_base_url = config['semaphore']['base_url']
    semaphore_username = config['semaphore']['username']
    semaphore_password = config['semaphore']['password']

    awx_base_url = config['awx']['base_url']
    awx_username = config['awx']['username']
    awx_password = config['awx']['password']


    rabbitmq_host = config['message_broker']['host']
    queue_name = config['message_broker']['queue_name']

    secret = config['credential']['secret']

    logger.info('Properties sure_tosca_base_url: ' + sure_tosca_base_url + ', semaphore_base_url: ' + semaphore_base_url
                + ', rabbitmq_host: ' + rabbitmq_host+ ', queue_name: '+queue_name)

    channel, connection = init_channel(rabbitmq_host, queue_name)
    logger.info("v1.0.3")
    logger.info("Awaiting RPC requests")
    try:
        thread = Thread(target=threaded_function, args=(1,))
        thread.start()
        start(channel)
    except Exception as e:
        done = True
        e = sys.exc_info()[0]
        logger.info("Error: " + str(e))
        print(e)
        exit(-1)
