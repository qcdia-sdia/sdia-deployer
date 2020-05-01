# To change this license header, choose License Headers in Project Properties.
# To change this template file, choose Tools | Templates
# and open the template in the editor.
import json
import os
import os.path
import tempfile
import time
import logging
import pika
import yaml
import sys
from time import sleep
from concurrent.futures import thread
from threading import Thread

from service import ansible_service
import sure_tosca_client

logger = logging.getLogger(__name__)

done = False


# if not getattr(logger, 'handler_set', None):
# logger.setLevel(logging.INFO)
# h = logging.StreamHandler()
# formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# h.setFormatter(formatter)
# logger.addHandler(h)
# logger.handler_set = True


def init_chanel(args):
    global rabbitmq_host
    if len(args) > 1:
        rabbitmq_host = args[1]
        queue_name = args[2]  # deployer
    else:
        rabbitmq_host = '127.0.0.1'

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


def init_sure_tosca_client(sure_tosca_base_path):
    configuration = sure_tosca_client.Configuration()
    sure_tosca_client.configuration.host = sure_tosca_base_path
    api_client = sure_tosca_client.ApiClient(configuration=configuration)
    sure_tosca_client_api = sure_tosca_client.api.default_api.DefaultApi(api_client=api_client)  # noqa: E501
    return sure_tosca_client_api


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

    print(yaml.dump(tosca_template_dict))

    sure_tosca_client.upload_tosca_template()
    # tosca_interfaces = tosca.get_interfaces(tosca_template_dict)
    # tmp_path = tempfile.mkdtemp()
    # vms = tosca.get_vms(tosca_template_dict)
    # inventory_path = ansible_service.write_inventory_file(tmp_path, vms)
    # paths = ansible_service.write_playbooks_from_tosca_interface(tosca_interfaces, tmp_path)

    # tokens = {}
    # for playbook_path in paths:
    #     out, err = ansible_service.run(inventory_path, playbook_path)
    #     api_key, join_token, discovery_token_ca_cert_hash = ansible_service.parse_api_tokens(out.decode("utf-8"))
    #     if api_key:
    #         tokens['api_key'] = api_key
    #     if join_token:
    #         tokens['join_token'] = join_token
    #     if discovery_token_ca_cert_hash:
    #         tokens['discovery_token_ca_cert_hash'] = discovery_token_ca_cert_hash
    #
    # ansible_playbook_path = k8s_service.write_ansible_k8s_files(tosca_template_dict, tmp_path)
    # out, err = ansible_service.run(inventory_path, ansible_playbook_path)
    # dashboard_token = ansible_service.parse_dashboard_tokens(out.decode("utf-8"))
    # tokens['dashboard_token'] = dashboard_token
    #
    # tosca_template_dict = tosca.add_tokens(tokens, tosca_template_dict)
    # tosca_template_dict = tosca.add_dashboard_url(k8s_service.get_dashboard_url(vms), tosca_template_dict)
    # tosca_template_dict = tosca.add_service_url(k8s_service.get_service_urls(vms, tosca_template_dict),
    #                                             tosca_template_dict)

    response = {'toscaTemplate': tosca_template_dict}
    output_current_milli_time = int(round(time.time() * 1000))
    response["creationDate"] = output_current_milli_time
    logger.info("Returning Deployment")
    logger.info("Output message:" + json.dumps(response))
    return json.dumps(response)


def threaded_function(args):
    while not done:
        connection.process_data_events()
        sleep(5)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    if sys.argv[1] == "test_local":
        tosca_path = "../TOSCA/"
        input_tosca_file_path = tosca_path + '/application_example_provisioned.yaml'

        with open(input_tosca_file_path) as f:
            # use safe_load instead load
            tosca_template_json = yaml.safe_load(f)

    else:
        logger.info("Input args: " + sys.argv[0] + ' ' + sys.argv[1] + ' ' + sys.argv[2])
        global channel, queue_name, connection, sure_tosca_client
        channel, connection = init_chanel(sys.argv)
        queue_name = sys.argv[2]
        sure_tosca_base_url = sys.argv[3]  # "http://localhost:8081/tosca-sure/1.0.0/"
        sure_tosca_client = init_sure_tosca_client(sure_tosca_base_url)
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
