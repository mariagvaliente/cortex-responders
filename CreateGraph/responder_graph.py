#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder

import requests
import base64
import magic

from thehive4py.api import TheHiveApi
from thehive4py.query import *
from thehive4py.models import AlertArtifact
from thehive4py.models import Alert

from cortex4py.api import Api

import sys
import json
import re

import networkx as nx
import matplotlib.pyplot as plt

from thehive_config import THE_HIVE_API_KEY, CORTEX_API_KEY, THE_HIVE_URL, CORTEX_URL

import os
from datetime import datetime

from dateutil.parser import parse

import tempfile
import pathlib
import ntpath
from shutil import copyfileobj

api = TheHiveApi(THE_HIVE_URL, THE_HIVE_API_KEY)
cortex_api = Api(CORTEX_URL, CORTEX_API_KEY)

class createGraph(Responder):

  def __init__(self):
      Responder.__init__(self)
      
  def get_jobs(self):
    
      # Descarga todos los jobs en la plataforma
      # return: listado de todos los jobs ejecutados con exito
      # Construimos la query para traernos todos los jobs que se han completado con exito
    
      data = json.dumps({"query": {"_and": [{"status": "Success"},]}})
      req = CORTEX_URL + "/api/job/_search?range=all"
      headers = {'Authorization': 'Bearer {}'.format(CORTEX_API_KEY), 'Content-Type': 'application/json'}
      response = requests.post(req, headers=headers, data=data)
      
      if response.status_code == 200:
         return response.json()
      else:
         print('get_jobs() Error: ' + str(response.status_code))
         return None

      
  def run(self):
      Responder.run(self)
      data_case = self.get_param('data', None, 'data')
      print(data_case)
      jobs = self.get_jobs()
      # Sacamos el id del caso
      case_id = data_case.get('id')
      # Diccionario para almacenar los resultados de la score_social de cada artifact que se va a devolver en el report del responder
      records = {}
      # Creamos el grafo
      labels = {}
      G = nx.DiGraph()
           
      # Sacamos los observables de un caso

      response = api.get_case_observables(case_id)

      if response.status_code == 200:
          observables = response.json()
      else:
          print('get_case_observables() Error: ' + response.content)
          exit(1)

      print(json.dumps(response.json(), indent=4, sort_keys=True))
      
      # Lista para almacenar los observables 'hijos' que han sido importados al caso como artifacts de un observable 'padre'
      obs_children = []
      # Lista para almacenar los observables 'padres' del caso
      obs_parents = []
      # Recorremos todos los observables 
      for o in observables:
          # Si el observable contiene el mensaje 'Discovered from' significa que ha sido importado desde un artifact por lo que se guarda en la lista de observables 'hijos'
          # Si no contiene ese mensaje se guarda en la lista de observables 'padres'
          if o.get('message').find('### Discovered from:') == -1:
             obs_parents.append(o)
          else:
             obs_children.append(o.get('data'))

      # Inicializamos la variable donde se guardara el score agregado del observable
      score_aggregated_obs = 0.0
      # Inicializamos la variable donde se guardara el score agegado del artifact importado procedente de un observable
      score_aggregated_art = 0.0
      # Inicializamos la variable donde se guardara la relacion entre observable y artifact
      relation = ''
      
      for observable in observables:
          # Dentro de cada observable recorremos los reports
          # y sacamos los artifacts de cada report buscando por analizador y 
          # por el id de artifact
          print(observable)
          if 'attachment' in observable:
              continue

          node_id = observable['data']
          
          # Si el observable no esta pintado en el grafo y ademas es un observable 'padre', lo pintamos como un nodo y guardamos en score_aggregated_obs la score agregada del observable
          # Si no se cumple lo anterior, estamos ante un observable 'hijo' por lo que no lo pintamos y solo guardamos su score agregada en score_aggregated_obs
          if node_id not in G and observable in obs_parents:
              G.add_node(node_id)
              G.nodes[node_id]['dataType'] = observable['dataType']
              G.nodes[node_id]['data'] = observable['data']
              for tag in observable['tags']:
                  if tag.find("Score_aggregated") >= 0:
                     score_aggregated = re.findall("[+-]?\\d+\\.\\d+", tag)
              if len(score_aggregated) != 0:
                 score_aggregated_obs = score_aggregated[0]   
          else:
              for tag in observable['tags']:
                  if tag.find("Score_aggregated") >= 0:
                     score_aggregated = re.findall("[+-]?\\d+\\.\\d+", tag)
              if len(score_aggregated) != 0:
                 score_aggregated_obs = score_aggregated[0] 

          artifact_id = observable['id']

          for report_name in observable['reports'].keys():

              print(report_name)

              analyzer = cortex_api.analyzers.get_by_name(report_name)

              if analyzer is None:
                  print('{}: analizador no encontrado'.format(report_name))
                  continue

              print (report_name, analyzer.name, analyzer.id)

              analyzer_id = analyzer.id
            
              # La busqueda de jobs asociados a un analizador y un observable debe hacerse mediante el API
              # de Cortex pero desgraciadamente no funciona. No se pueden hacer búsqueda por 'data' porque ese campo no está indexado
            
              # Alternativamente, optamos por bajarnos TODOS los jobs de Cortex y despues filtramos por el valor del observable en cada caso
            
              # Es poco optimo, no escala pero es un workaround hasta que arreglen esto en Cortex       
            

              jobs_observable = filter(lambda x: x['data'] == observable['data'], jobs)
  
              print("Numero de jobs encontrados: {}".format(len(response.json())))
  
              # La respuesta contiene los jobs asociado a ese observable y ese analizador
              # Deberiamos quedarnos unicamente con el mas reciente
  
              for job in jobs_observable:
                  # Listamos todos los artifacts que se extraen del observable
  
                  artifacts = cortex_api.jobs.get_artifacts(job['id'])

                  # Recorremos cada uno de los artifacts asociados al observable
                  for artifact in artifacts:
                      try:
                          # Si el artifact existe y ademas es un observable 'hijo' (es decir, ha sido importado al caso como observable) 
                          if artifact.data and artifact.data in obs_children:
                             # Si el artifact no ha sido pintado en el grafo y ademas no es igual que el observable (esto es para evitar pintar relaciones con uno mismo), lo pintamos
                             if artifact.data not in G and artifact.data != observable['data']:
                                # Aqui vamos añadiendo nodos. Seria más elegante añadir aristas y nodos a una lista
                                # Y crear el grafo al final
                                
                                # Establecemos la relacion entre el observable y el artifact, y guardamos el factor de propagacion de malignidad en funcion del tipo de relacion
                                if observable['dataType'] == 'hash' and artifact.dataType == 'domain':
                                   relation = 'hash-domain'
                                   factor = 1
                                elif observable['dataType'] == 'hash' and artifact.dataType == 'ip':
                                   relation = 'hash-ip'
                                   factor = 1
                                elif observable['dataType'] == 'hash' and artifact.dataType == 'url':
                                   relation = 'hash-url'
                                   factor = 1
                                elif observable['dataType'] == 'hash' and artifact.dataType == 'attack_pattern':
                                   relation = 'hash-attack_pattern'
                                   factor = 0.5
                                elif observable['dataType'] == 'hash' and artifact.dataType == 'malware_family':
                                   relation = 'hash-malware_family'
                                   factor = 1
                                elif observable['dataType'] == 'hash' and artifact.dataType == 'campaign':
                                   relation = 'hash-campaign'
                                   factor = 1
                                elif observable['dataType'] == 'hash' and artifact.dataType == 'vulnerability':
                                   relation = 'hash-vulnerability'
                                   factor = 1
                                elif observable['dataType'] == 'hash' and artifact.dataType == 'exploit':
                                   relation = 'hash-exploit'
                                   factor = 0.5
                                elif observable['dataType'] == 'hash' and artifact.dataType == 'threat_actor':
                                   relation = 'hash-threat_actor'
                                   factor = 0.5       
                                elif observable['dataType'] == 'domain' and artifact.dataType == 'domain':
                                   relation = 'domain-domain'
                                   factor = 0.3
                                elif observable['dataType'] == 'domain' and artifact.dataType == 'ip':
                                   relation = 'domain-ip'
                                   factor = 0.6
                                elif observable['dataType'] == 'domain' and artifact.dataType == 'hash':
                                   relation = 'domain-hash'
                                   factor = 1
                                elif observable['dataType'] == 'domain' and artifact.dataType == 'url':
                                   relation = 'domain-url'
                                   factor = 0.6
                                elif observable['dataType'] == 'domain' and artifact.dataType == 'filename':
                                   relation = 'domain-file'
                                   factor = 1
                                elif observable['dataType'] == 'ip' and artifact.dataType == 'domain':
                                   relation = 'ip-domain'
                                   factor = 0.6
                                elif observable['dataType'] == 'ip' and artifact.dataType == 'hash':
                                   relation = 'ip-hash'
                                   factor = 1
                                elif observable['dataType'] == 'ip' and artifact.dataType == 'url':
                                   relation = 'ip-url'
                                   factor = 0.6
                                elif observable['dataType'] == 'ip' and artifact.dataType == 'filename':
                                   relation = 'ip-file'
                                   factor = 1
                                elif observable['dataType'] == 'url' and artifact.dataType == 'domain':
                                   relation = 'url-domain'
                                   factor = 0.6
                                elif observable['dataType'] == 'url' and artifact.dataType == 'ip':
                                   relation = 'url-ip'
                                   factor = 0.6
                                elif observable['dataType'] == 'url' and artifact.dataType == 'hash':
                                   relation = 'url-hash'
                                   factor = 1
                                elif observable['dataType'] == 'url' and artifact.dataType == 'filename':
                                   relation = 'url-file'
                                   factor = 1
                                
                                # Recorremos los observables para sacar la score agregada del artifact y guardarla en score_aggregated_art
                                for o in observables:
                                    if artifact.data == o.get('data'):
                                       for tag in o.get('tags'):
                                           if tag.find("Score_aggregated") >= 0:
                                              score_aggregated_artifact = re.findall("[+-]?\\d+\\.\\d+", tag)
                                       if len(score_aggregated_artifact) != 0:
                                          score_aggregated_art = score_aggregated_artifact[0]
                                          
                                # Añadimos el nodo
                                G.add_node(artifact.data, dataType=artifact.dataType, data=artifact.data)
                                # Llamamos a la funcion scoreSocial para calcular la score social del artifact pasando como parametro el factor de propagacion de malicia y las scores tanto del observable 'padre' como del artifact
                                score_social = self.scoreSocial(factor, score_aggregated_obs, score_aggregated_art)
                                # Guardamos la score social asociada al artifact en el diccionario records
                                records["Score_social of " + artifact.data] = str(score_social)
                                # Añadimos la arista 
                                G.add_edge(node_id, artifact.data, analyzer=report_name, relation=relation, score_observable=score_aggregated_obs, score_artifact=score_aggregated_art, score_social=score_social)
                                
                                # Recorremos los observables para crear una nueva etiqueta con el score social en cada observable 'hijo'
                                for o in observables:
                                    if artifact.data == o.get('data'):
                                       if o.get('data') in obs_children:
                                           tags = []
                                           for tag in o.get('tags'):
                                               tags.append(tag)
                                           social = "Score_social: " + str(score_social)
                                           if social not in tags:
                                              tags.append(social)
                                           data = json.dumps({"tags": tags})
                                           req = THE_HIVE_URL + "/api/case/artifact/" + str(o['_id'])
                                           headers = {'Authorization': 'Bearer {}'.format(THE_HIVE_API_KEY), 'Content-Type': 'application/json'}
                                           response = requests.patch(req, headers=headers, data=data)
                                
                      except AttributeError:

                          # Hay algunos casos en que no existe el atributo data: los ignoramos

                          print("Attribute Error: " + str(artifact))
                          continue


      # Guardamos todos los reports del observable
      self.report(records)
  

      # Aqui definimos los colores de los distintos tipos de nodo para networkx

      colormap = {"threat_actor": "red", "malicious_behaviour": "orange", "attack_pattern": "black",
                  "file": "green", "hash": "white", "ip":"blue","domain":"yellow"}
  
      node_colors = []
  
      for node in G.nodes:
          try:
  
              if 'dataType' in G.nodes[node]:
                  node_colors.append(colormap[G.nodes[node]['dataType']])
  
          except KeyError:
              # Si no hemos definido color, lo dejamos en negro

              node_colors.append('black')
              continue
  
      pos = nx.spring_layout(G)
  
      for node in G.nodes:
          labels[node] = G.nodes[node]['data']
  
      plt.figure(figsize=(20, 14))
  
  
      # https://stackoverflow.com/questions/21978487/improving-python-networkx-graph-layout
    
      nx.draw(G, node_color=node_colors, labels=labels, pos=nx.nx_pydot.graphviz_layout(G), \
              node_size=1200,  linewidths=0.25, \
              font_size=10, font_weight='bold', with_labels=True, dpi=1000)
  
  
  
      # Guardamos el grafo en formato Graphml
     
      nx.write_graphml(G,"/tmp/graph.graphml")
      file_path = "/tmp/graph.graphml"
      
      # Creamos una alerta para mandar el grafo generado
      # Llamamos a la funcion createAlert() pasando como parametro en nombre del caso (case_name) y el path del fichero con el grafo (file_path)
      
      case_name = data_case.get('title')
      self.createAlert(case_name, file_path)

  # Funcion para crear una alerta con un file asociado 
  def createAlert(self, case_name, file_path):
      with open(file_path, "rb") as file_artifact:
            filename = os.path.basename(file_path)
            mime = magic.Magic(mime=True).from_file(file_path)
            encoded_string = base64.b64encode(file_artifact.read())
      artifact = "{};{};{}".format(filename, mime, encoded_string.decode())
      data = json.dumps({"title": "Graph created", "description": "Relations between observables of a case shown in a graphml", "type": "external", "source": case_name, "sourceRef": "alertGraph2", "artifacts": [{"dataType": "file", "data": artifact, "message": "graph"}]})
      print(data)
      req = THE_HIVE_URL + "/api/alert"
      headers = {'Authorization': 'Bearer {}'.format(THE_HIVE_API_KEY), 'Content-Type': 'application/json'}
      response = requests.post(req, headers=headers, data=data)
      
      if response.status_code == 201:
         print(response.json())
         return response.json()
      else:
         print('createAlert() Error: ' + str(response.status_code))
         return None
         
  # Funcion para calcular la score social asociada a un artifact
  def scoreSocial(self, factor, score_aggregated_obs, score_aggregated_art):
      div = (float(factor) * float(score_aggregated_obs))/5
      mult = (5 - float(score_aggregated_art)) * div
      result = float(score_aggregated_art) + mult
      return result


if __name__ == '__main__':
   createGraph().run()