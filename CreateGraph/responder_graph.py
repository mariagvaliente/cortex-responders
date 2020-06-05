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
         
  def get_artifacts(self, job_id):
  
      # Obtiene los artefactos asociados a cada uno de los observables
      # Recibe como parametro el id del job correspondiente con el observable
      # Realiza esta consulta:
      # curl -H 'Authorization: Bearer **API_KEY**' 'https://CORTEX_APP_URL:9001/api/job/JOB_ID/artifacts?range=all'
      # Añadimos range=all para que obtenga todos
      # Devuelve el listado con todos los artefactos
      
      req = CORTEX_URL + "/api/job/" + job_id + "/artifacts?range=all"

      headers = {'Authorization': 'Bearer {}'.format(CORTEX_API_KEY)}

      response = requests.get(req, headers=headers)

      if response.status_code == 200:
         return response.json()
      else:
         print('get_artifacts() Error: ' + str(response.status_code))
         return None   

      
  def run(self):
      Responder.run(self)
      data_case = self.get_param('data', None, 'data')
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
      
      # Lista para almacenar los datos de todos los observables
      obs = []
      # Recorremos todos los observables y guardamos en la lista obs los datos de cada observable
      for o in observables:
          obs.append(o.get('data'))


      # Inicializamos la variable donde se guardara la relacion entre observable y artifact
      relation = ''
      # Inicializamos la variable donde se guardara el factor de propagacion de malicia
      factor = 0.0
      
      for observable in observables:
          # Dentro de cada observable recorremos los reports
          # y sacamos los artifacts de cada report buscando por analizador y 
          # por el id de artifact
          if 'attachment' in observable:
              continue

          node_id = observable['data']
          
          # Si el observable no esta pintado en el grafo, lo pintamos como un nodo y guardamos en score_aggregated la score agregada del observable
          # Si el observable ya esta en el grafo, no lo pintamos y solo guardamos su score agregada en score_aggregated
          if node_id != None:
            if node_id not in G: 
                G.add_node(node_id)
                G.nodes[node_id]['dataType'] = observable['dataType']
                G.nodes[node_id]['data'] = observable['data']
                if G.nodes[node_id]['dataType'] not in descriptive_nodes:
                   for tag in observable['tags']:
                       if tag.find("Score_aggregated") >= 0:
                          score_aggregated = re.findall("[+-]?\\d+\\.\\d+", tag)
                          G.nodes[node_id]['score_aggregated'] = score_aggregated[0]
            else:
                if G.nodes[node_id]['dataType'] not in descriptive_nodes:
                   for tag in observable['tags']:
                       if tag.find("Score_aggregated") >= 0:
                          score_aggregated = re.findall("[+-]?\\d+\\.\\d+", tag)
                          G.nodes[node_id]['score_aggregated'] = score_aggregated[0]

          artifact_id = observable['id']

          for report_name in observable['reports'].keys():
            
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
  
                  artifacts = self.get_artifacts(job["id"])

                  # Recorremos cada uno de los artifacts asociados al observable
                  for artifact in artifacts:
                      try:
                          # Si el artifact existe y ademas es un observable (es decir, ha sido importado al caso como observable) 
                          if artifact['data'] and artifact['data'] in obs:
                             # Si el artifact no ha sido pintado en el grafo, lo pintamos
                             if artifact['data'] not in G:
                                 # Añadimos el nodo
                                 G.add_node(artifact['data'], dataType=artifact['dataType'], data=artifact['data'])
                                
                             # Comprobamos el artifact asociado al observable no es igual al observable, ya que si fueran iguales estariamos estableciendo una arista consigo mismo
                             if artifact['data'] != observable['data']:
                               # Establecemos la relacion entre el observable y el artifact, y guardamos el factor de propagacion de malignidad en funcion del tipo de relacion
                                 if observable['dataType'] == 'hash' and artifact['dataType'] == 'domain':
                                    relation = 'hash-domain'
                                    factor = 1.0
                                 elif observable['dataType'] == 'hash' and artifact['dataType'] == 'ip':
                                    relation = 'hash-ip'
                                    factor = 1.0
                                 elif observable['dataType'] == 'hash' and artifact['dataType'] == 'url':
                                    relation = 'hash-url'
                                    factor = 1.0
                                 elif observable['dataType'] == 'hash' and artifact['dataType'] == 'hash':
                                    relation = 'hash-hash'
                                    factor = 0.5
                                 elif observable['dataType'] == 'hash' and artifact['dataType'] == 'attack_pattern':
                                    relation = 'hash-attack_pattern'
                                 elif observable['dataType'] == 'hash' and artifact['dataType'] == 'malware_family':
                                    relation = 'hash-malware_family'
                                 elif observable['dataType'] == 'hash' and artifact['dataType'] == 'campaign':
                                    relation = 'hash-campaign'
                                 elif observable['dataType'] == 'hash' and artifact['dataType'] == 'vulnerability':
                                    relation = 'hash-vulnerability'
                                 elif observable['dataType'] == 'hash' and artifact['dataType'] == 'exploit':
                                    relation = 'hash-exploit'
                                 elif observable['dataType'] == 'hash' and artifact['dataType'] == 'threat_actor':
                                    relation = 'hash-threat_actor'       
                                 elif observable['dataType'] == 'domain' and artifact['dataType'] == 'domain':
                                    relation = 'domain-domain'
                                    factor = 0.3
                                 elif observable['dataType'] == 'domain' and artifact['dataType'] == 'ip':
                                    relation = 'domain-ip'
                                    factor = 0.6
                                 elif observable['dataType'] == 'domain' and artifact['dataType'] == 'hash':
                                    relation = 'domain-hash'
                                    factor = 1.0
                                 elif observable['dataType'] == 'domain' and artifact['dataType'] == 'url':
                                    relation = 'domain-url'
                                    factor = 0.6
                                 elif observable['dataType'] == 'domain' and artifact['dataType'] == 'filename':
                                    relation = 'domain-file'
                                    factor = 1.0
                                 elif observable['dataType'] == 'ip' and artifact['dataType'] == 'domain':
                                    relation = 'ip-domain'
                                    factor = 0.6
                                 elif observable['dataType'] == 'ip' and artifact['dataType'] == 'hash':
                                    relation = 'ip-hash'
                                    factor = 1.0
                                 elif observable['dataType'] == 'ip' and artifact['dataType'] == 'url':
                                    relation = 'ip-url'
                                    factor = 0.6
                                 elif observable['dataType'] == 'ip' and artifact['dataType'] == 'filename':
                                    relation = 'ip-file'
                                    factor = 1.0
                                 elif observable['dataType'] == 'url' and artifact['dataType'] == 'domain':
                                    relation = 'url-domain'
                                    factor = 0.6
                                 elif observable['dataType'] == 'url' and artifact['dataType'] == 'ip':
                                    relation = 'url-ip'
                                    factor = 0.6
                                 elif observable['dataType'] == 'url' and artifact['dataType'] == 'hash':
                                    relation = 'url-hash'
                                    factor = 1.0
                                 elif observable['dataType'] == 'url' and artifact['dataType'] == 'filename':
                                    relation = 'url-file'
                                    factor = 1.0
                                 elif observable['dataType'] == 'email' and artifact['dataType'] == 'domain':
                                    relation = 'email-domain'
                                    factor = 0.6

                                 # Añadimos la arista
                                 G.add_edge(node_id, artifact['data'], relation=relation, factor=factor)
                                
                                
                      except AttributeError:

                          # Hay algunos casos en que no existe el atributo data: los ignoramos

                          print("Attribute Error: " + str(artifact))
                          continue


	    # Recorremos todos los nodos del grafo
	    for node in G.nodes():
	        scores_level_0 = []
	        factors_level_0 = []
	        scores_neighbors_level_1 = []
	        factors_neighbors_level_1 = []
	        scores_neighbors_level_2 = []
	        factors_neighbors_level_2 = []
	        
	        # Si el nodo no pertecene al grupo de nodos descriptivos
	        if G.nodes[node]['dataType'] not in descriptive_nodes:
	            # Extraemos la puntuacion agregada del nodo
	            score_node = G.nodes[node]['score_aggregated']
	            # Extraemos los nodos predecesores
	            predecessors = list(G.predecessors(node))
	            # Si existen nodos predecesores, calculamos la primera puntuacion social asociada al nodo
	            if len(predecessors) != 0:
	                # Recorremos todos los nodos predecesores
	                for predecessor in predecessors:
	                    # Guardamos la puntuacion agregada de cada nodo predecesor
	                    score_aggregated=G.nodes[predecessor]['score_aggregated']
	                    scores_level_0.append(score_aggregated)
	                    # Guardamos el factor de propagacion asociado a la relacion entre el nodo predecesor y el nodo actual para el que estamos calculando la puntuacion social
	                    factor = G[G.nodes[predecessor]['data']][G.nodes[node]['data']]['factor']
	                    factors_level_0.append(factor)
	                    # Calculamos la puntuacion social y la asociamos al nodo
	                    score_social_0 = scoreSocial(factors_level_0,scores_level_0,score_node)
	                    G.nodes[node]['score_social_0'] = score_social_0
	            # Extraemos todos los vecinos (tanto predecesores como sucesores) asociados al nodo para calcular las siguientes puntuaciones sociales
	            neighbors = list(set(list(nx.all_neighbors(G,node))))
	            # Si existen vecinos
	            if len(neighbors) != 0:
	                # Recorremos todos los vecinos
	                for neighbor in neighbors:
	                    # De cada nodo vecino, extraemos sus nodos vecinos, es decir, los vecinos de nuestros vecino
	                    neighbors_of_neighbors = list(set(list(nx.all_neighbors(G,neighbor))))
	                    # Si existen nodos vecinos de nuestro vecino
	                    if len(neighbors_of_neighbors) != 0:
	                        # Para cada nodo vecino de nuestro vecino
	                        for n1 in neighbors_of_neighbors:
	                            # Si el nodo vecino de nuestro vecino no pertenece al grupo de nodos descriptivos, no coincide con el nodo actual y además no coincide con nuestro vecino, calculamos la segunda puntuacion social
	                            if G.nodes[n1]['dataType'] not in descriptive_nodes and n1 != G.nodes[node]['data'] and n1 != neighbor:
	                                print(n1)
	                                # Extraemos la puntuacion agregada del nodo vecino de nuestro vecino
	                                scores_neighbors_level_1.append(G.nodes[n1]['score_aggregated'])
	                                # Si existe una arista entre el nodo vecino y el nodo actual, extraemos el factor de dicha relacion
	                                if G.has_edge(neighbor,node):
	                                    factor_neighbor_node = G[G.nodes[neighbor]['data']][G.nodes[node]['data']]['factor']
	                                else:
	                                    factor_neighbor_node = G[G.nodes[node]['data']][G.nodes[neighbor]['data']]['factor']
	                                # Si existe una arista entre el nodo vecino y el vecino del nodo vecino, extraemos el factor de dicha relacion
	                                if G.has_edge(neighbor,n1):
	                                    factor_neighbor_neighbor = G[G.nodes[neighbor]['data']][G.nodes[n1]['data']]['factor']
	                                else:
	                                    factor_neighbor_neighbor = G[G.nodes[n1]['data']][G.nodes[neighbor]['data']]['factor']

	                                # Multiplicamos dichos factores
	                                factor_mult = factor_neighbor_node * factor_neighbor_neighbor
	                                factors_neighbors_level_1.append(factor_mult)
	                                # Calculamos la segunda puntuacion social asociada al nodo actual influida por los nodos vecinos de sus vecinos
	                                score_social_1 = scoreSocial(factors_neighbors_level_1,scores_neighbors_level_1,score_node)
	                                G.nodes[node]['score_social_1'] = score_social_1

	                                # Extraemos todos los vecinos de los nodos vecinos de nuestros vecinos
	                                neighbors_of_neighbors_of_neighbors = list(set(list(nx.all_neighbors(G,n1))))
	                                # Si existen vecinos de los vecinos de nuestros vecinos
	                                if len(neighbors_of_neighbors_of_neighbors) != 0:
	                                    # Recorremos los nodos
	                                    for n2 in neighbors_of_neighbors_of_neighbors:
	                                        # Si el nodo no pertenece al grupo de nodos descriptivos, no coincide con el nodo actual y además no coincide ni con nuestro vecino ni con el vecino de nuestro vecino, calculamos la segunda puntuacion social
	                                        if G.nodes[n2]['dataType'] not in descriptive_nodes and n2 != G.nodes[node]['data'] and n2 != neighbor and n2 != n1:
	                                            # Extraemos la puntuacion social del nodo
	                                            scores_neighbors_level_2.append(G.nodes[n2]['score_aggregated'])
	                                            # Si existe una arista entre el nodo vecino y el nodo actual, extraemos el factor de dicha relacion
	                                            if G.has_edge(neighbor,node):
	                                                factor_neighbor_node = G[G.nodes[neighbor]['data']][G.nodes[node]['data']]['factor']
	                                            else:
	                                                factor_neighbor_node = G[G.nodes[node]['data']][G.nodes[neighbor]['data']]['factor']
	                                            # Si existe una arista entre el nodo vecino y vecino del nodo vecino, extraemos el factor de dicha relacion
	                                            if G.has_edge(neighbor,n1):
	                                                factor_neighbor_neighbor_1 = G[G.nodes[neighbor]['data']][G.nodes[n1]['data']]['factor']
	                                            else:
	                                                factor_neighbor_neighbor_1 = G[G.nodes[n1]['data']][G.nodes[neighbor]['data']]['factor']
	                                            # Si existe una arista entre el vecino del vecino del nodo vecino y el vecino del nodo vecino, extraemos el factor de dicha relacion
	                                            if G.has_edge(n1,n2):
	                                                factor_neighbor_neighbor_2 = G[G.nodes[n1]['data']][G.nodes[n2]['data']]['factor']
	                                            else:
	                                                factor_neighbor_neighbor_2 = G[G.nodes[n2]['data']][G.nodes[n1]['data']]['factor']

	                                            # Multiplicamos los factores
	                                            factor_mult = factor_neighbor_node * factor_neighbor_neighbor_1 * factor_neighbor_neighbor_2
	                                            factors_neighbors_level_2.append(factor_mult)
	                                            # Calculamos la tercera puntuacion social asociada al nodo actual influida en este caso por los nodos vecinos de los vecinos de sus vecinos
	                                            score_social_2 = scoreSocial(factors_neighbors_level_2,scores_neighbors_level_2,score_node)
	                                            G.nodes[node]['score_social_2'] = score_social_2


	        # Por ultimo, recorremos todos los observables y cuando el observable sea igual al nodo, obtenemos sus etiquetas y generamos una nueva con la puntuacion social asociada
	        # for o in observables:
	        #     if G.nodes[node]['data'] == o.get('data'):
	        #        tags = []
	        #        for tag in o.get('tags'):
	        #            tags.append(tag)
	        #        social = "Score_social: " + str(score_social)
	        #        tags.append(social)
	        #        data = json.dumps({"tags": tags})
	        #        req = THE_HIVE_URL + "/api/case/artifact/" + str(o['_id'])
	        #        headers = {'Authorization': 'Bearer {}'.format(THE_HIVE_API_KEY), 'Content-Type': 'application/json'}
	        #        response = requests.patch(req, headers=headers, data=data)
        

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
      
      # Devolvemos el siguiente report al ejecutar el responder
      records = {"results": "An alert has been generated with the graph file"}
      self.report(records)
  

  # Funcion para crear una alerta con un fichero asociado 
  def createAlert(self, case_name, file_path):
      with open(file_path, "rb") as file_artifact:
            filename = os.path.basename(file_path)
            mime = magic.Magic(mime=True).from_file(file_path)
            encoded_string = base64.b64encode(file_artifact.read())
      artifact = "{};{};{}".format(filename, mime, encoded_string.decode())
      data = json.dumps({"title": "Graph generated", "description": "Relations between observables of a case shown in a graphml", "type": "external", "source": "graph", "sourceRef": "CreateGraph", "artifacts": [{"dataType": "file", "data": artifact, "message": "graph"}]})
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
         
  # Funcion para calcular la puntuacion social asociada a un nodo
  def scoreSocial(factors, scores, score_node):
      d = 0
      div = 0
      for s in scores:
          d = d + 5

      factors = list(map(str, factors))
      for s,f in zip(scores, factors):
          div = div + (float(f) * float(s))

      div = div/d
      mult = (5 - float(score_node)) * div
      result = float(score_node) + mult
      return result


if __name__ == '__main__':
   createGraph().run()