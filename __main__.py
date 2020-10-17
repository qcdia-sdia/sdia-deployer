# To change this license header, choose License Headers in Project Properties.
# To change this template file, choose Tools | Templates
# and open the template in the editor.
import configparser
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


def init_chanel(rabbitmq_host, queue_name):
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
    with open(tosca_template_path, 'w') as outfile:
        yaml.dump(tosca_template_dict, outfile, default_flow_style=False)
    return  tosca_template_path


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

    tosca_template_path = save_tosca_template(tosca_template_dict)

    tosca_helper = ToscaHelper(sure_tosca_base_url, tosca_template_path)
    # nodes_to_deploy = tosca_helper.get_application_nodes()
    nodes = tosca_helper.get_deployment_node_pipeline()

    deployService = DeployService(semaphore_base_url=semaphore_base_url, semaphore_username=semaphore_username,
                                  semaphore_password=semaphore_password, vms=tosca_helper.get_vms())
    try:
        for node in nodes:
            updated_node = deployService.deploy(node)
            if isinstance(updated_node, list):
                for node in updated_node:
                    tosca_template_dict = tosca_helper.set_node(node,tosca_template_dict)
                    # logger.info("tosca_template_dict :" + json.dumps(tosca_template_dict))
            else:
                tosca_template_dict = tosca_helper.set_node(updated_node, tosca_template_dict)
                # logger.info("tosca_template_dict :" + json.dumps(tosca_template_dict))

        response = {'toscaTemplate': tosca_template_dict}
        output_current_milli_time = int(round(time.time() * 1000))
        response["creationDate"] = output_current_milli_time
        logger.info("Returning Deployment")
        logger.info("Output message:" + json.dumps(response))
        return json.dumps(response)
    except Exception as e:
        track = traceback.format_exc()
        print(track)
        raise


def threaded_function(args):
    while not done:
        connection.process_data_events()
        sleep(8)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    global channel, queue_name, connection, rabbitmq_host, sure_tosca_base_url,semaphore_base_url, semaphore_username, \
        semaphore_password

    config = configparser.ConfigParser()
    config.read('properties.ini')
    sure_tosca_base_url = config['tosca-sure']['base_url']
    semaphore_base_url = config['semaphore']['base_url']
    semaphore_username = config['semaphore']['username']
    semaphore_password = config['semaphore']['password']

    rabbitmq_host = config['message_broker']['host']
    queue_name = config['message_broker']['queue_name']

    logger.info('Properties sure_tosca_base_url: ' + sure_tosca_base_url + ', semaphore_base_url: ' + semaphore_base_url
                + ', rabbitmq_host: ' + rabbitmq_host+ ', queue_name: '+queue_name)

    channel, connection = init_chanel(rabbitmq_host, queue_name)

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
