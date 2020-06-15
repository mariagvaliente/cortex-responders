#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder

import requests
import base64
import magic

from thehive4py.api import TheHiveApi

from cortex4py.api import Api

from thehive_config import THE_HIVE_API_KEY, CORTEX_API_KEY, THE_HIVE_URL, CORTEX_URL

import sys
import json
import re
import os

import networkx as nx

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

      #print(json.dumps(response.json(), indent=4, sort_keys=True))
      
      # Lista para almacenar los datos de todos los observables
      obs = []
      # Recorremos todos los observables y guardamos en la lista obs los datos de cada observable
      for o in observables:
          obs.append(o.get('data'))

      # Inicializamos la variable donde se guardara la relacion entre observable y artifact
      relation = ''
      # Inicializamos la variable donde se guardara el factor de propagacion de malicia
      factor = 0.0
      # Grupo de nodos con los que solo se establece relacion pero no se calcula ninguna puntuacion
      descriptive_nodes = ["attack_pattern", "malware_family", "campaign", "exploit", "vulnerability", "threat_actor"]
      
      
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

                             # Si el artifact no es a su vez el observable (para evitar relaciones con uno mismo), se añade una arista con la relacion y el factor de propagacion asociado
                             if artifact['data'] != observable['data']:
                                if observable['dataType'] == 'hash' and artifact['dataType'] == 'domain':
                                   relation = 'hash-domain'
                                   factor = 1.0
                                   G.add_edge(node_id, artifact['data'], relation=relation, factor=factor)
                                elif observable['dataType'] == 'hash' and artifact['dataType'] == 'ip':
                                   relation = 'hash-ip'
                                   factor = 1.0
                                   G.add_edge(node_id, artifact['data'], relation=relation, factor=factor)
                                elif observable['dataType'] == 'hash' and artifact['dataType'] == 'url':
                                   relation = 'hash-url'
                                   factor = 1.0
                                   G.add_edge(node_id, artifact['data'], relation=relation, factor=factor)
                                elif observable['dataType'] == 'hash' and artifact['dataType'] == 'hash':
                                   relation = 'hash-hash'
                                   factor = 0.5
                                   G.add_edge(node_id, artifact['data'], relation=relation, factor=factor)
                                elif observable['dataType'] == 'hash' and artifact['dataType'] == 'filename':
                                   relation = 'hash-file'
                                   factor = 0.5
                                   G.add_edge(node_id, artifact['data'], relation=relation, factor=factor)
                                elif observable['dataType'] == 'hash' and artifact['dataType'] == 'attack_pattern':
                                   relation = 'hash-attack_pattern'
                                   G.add_edge(node_id, artifact['data'], relation=relation)
                                elif observable['dataType'] == 'hash' and artifact['dataType'] == 'malware_family':
                                   relation = 'hash-malware_family'
                                   G.add_edge(node_id, artifact['data'], relation=relation)
                                elif observable['dataType'] == 'hash' and artifact['dataType'] == 'campaign':
                                   relation = 'hash-campaign'
                                   G.add_edge(node_id, artifact['data'], relation=relation)
                                elif observable['dataType'] == 'hash' and artifact['dataType'] == 'vulnerability':
                                   relation = 'hash-vulnerability'
                                   G.add_edge(node_id, artifact['data'], relation=relation)
                                elif observable['dataType'] == 'hash' and artifact['dataType'] == 'exploit':
                                   relation = 'hash-exploit'
                                   G.add_edge(node_id, artifact['data'], relation=relation)
                                elif observable['dataType'] == 'hash' and artifact['dataType'] == 'threat_actor':
                                   relation = 'hash-threat_actor'    
                                   G.add_edge(node_id, artifact['data'], relation=relation)       
                                elif observable['dataType'] == 'domain' and artifact['dataType'] == 'domain':
                                   relation = 'domain-domain'
                                   factor = 0.3
                                   G.add_edge(node_id, artifact['data'], relation=relation, factor=factor)
                                elif observable['dataType'] == 'domain' and artifact['dataType'] == 'ip':
                                   relation = 'domain-ip'
                                   factor = 0.6
                                   G.add_edge(node_id, artifact['data'], relation=relation, factor=factor)
                                elif observable['dataType'] == 'domain' and artifact['dataType'] == 'hash':
                                   relation = 'domain-hash'
                                   factor = 1.0
                                   G.add_edge(node_id, artifact['data'], relation=relation, factor=factor)
                                elif observable['dataType'] == 'domain' and artifact['dataType'] == 'url':
                                   relation = 'domain-url'
                                   factor = 0.6
                                   G.add_edge(node_id, artifact['data'], relation=relation, factor=factor)
                                elif observable['dataType'] == 'ip' and artifact['dataType'] == 'domain':
                                   relation = 'ip-domain'
                                   factor = 0.6
                                   G.add_edge(node_id, artifact['data'], relation=relation, factor=factor)
                                elif observable['dataType'] == 'ip' and artifact['dataType'] == 'hash':
                                   relation = 'ip-hash'
                                   factor = 1.0
                                   G.add_edge(node_id, artifact['data'], relation=relation, factor=factor)
                                elif observable['dataType'] == 'ip' and artifact['dataType'] == 'url':
                                   relation = 'ip-url'
                                   factor = 0.6
                                   G.add_edge(node_id, artifact['data'], relation=relation, factor=factor)
                                elif observable['dataType'] == 'url' and artifact['dataType'] == 'domain':
                                   relation = 'url-domain'
                                   factor = 0.6
                                   G.add_edge(node_id, artifact['data'], relation=relation, factor=factor)
                                elif observable['dataType'] == 'url' and artifact['dataType'] == 'ip':
                                   relation = 'url-ip'
                                   factor = 0.6
                                   G.add_edge(node_id, artifact['data'], relation=relation, factor=factor)
                                elif observable['dataType'] == 'url' and artifact['dataType'] == 'hash':
                                   relation = 'url-hash'
                                   factor = 1.0
                                   G.add_edge(node_id, artifact['data'], relation=relation, factor=factor)
                                elif observable['dataType'] == 'url' and artifact['dataType'] == 'filename':
                                   relation = 'url-file'
                                   factor = 1.0
                                   G.add_edge(node_id, artifact['data'], relation=relation, factor=factor)
                                elif observable['dataType'] == 'email' and artifact['dataType'] == 'domain':
                                   relation = 'email-domain'
                                   factor = 0.6
                                   G.add_edge(node_id, artifact['data'], relation=relation, factor=factor)                              
                               

                      except AttributeError:
                            '''
                            Hay algunos casos en que no existe el atributo data: los ignoramos
                            '''
                            print("Attribute Error: " + str(artifact))
                            continue


      # # Recorremos todos los nodos del grafo para calcular la primera puntuacion social
      for node in G.nodes():
          scores_level_initial = []
          factors_level_initial = []
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
                    scores_level_initial.append(score_aggregated)
                    # Guardamos el factor de propagacion asociado a la relacion entre el nodo predecesor y el nodo actual para el que estamos calculando la puntuacion social
                    factor = G[G.nodes[predecessor]['data']][G.nodes[node]['data']]['factor']
                    factors_level_initial.append(factor)
                    # Calculamos la puntuacion social y la asociamos al nodo
                    score_social_initial = self.scoreSocial(factors_level_initial,scores_level_initial,score_node)
                    G.nodes[node]['score_social'] = score_social_initial
             else:
                 G.nodes[node]['score_social'] = score_node

      # # Recorremos todos los nodos del grafo para calcular la puntuacion social final
      for node in G.nodes():
          scores_level_final = []
          factors_level_final = []
          predecessors_of_predecessor = []

          # Si el nodo no pertecene al grupo de nodos descriptivos
          if G.nodes[node]['dataType'] not in descriptive_nodes:
             # Extraemos los nodos predecesores
             predecessors = list(G.predecessors(node))
             # Extraemos los nodos predecesores de los predecesores
             for predecessor in predecessors:
                 new_predecessors = list(G.predecessors(predecessor))
                 if len(new_predecessors) != 0:
                    for p in new_predecessors:
                       predecessors_of_predecessor.append(p)               

             # Si existen nodos predecesores y los predecesores a su vez tienen predecesores, calculamos la puntuacion social final asociada al nodo
             if len(predecessors) != 0 and len(predecessors_of_predecessor) != 0:
                # Extraemos la puntuacion social inicial del nodo
                score_node = G.nodes[node]['score_social']
                # Recorremos todos los nodos predecesores
                for predecessor in predecessors:
                    # Guardamos la puntuacion social de cada nodo predecesor
                    score_social_predecessor=G.nodes[predecessor]['score_social']
                    scores_level_final.append(score_social_predecessor)
                    # Guardamos el factor de propagacion asociado a la relacion entre el nodo predecesor y el nodo actual para el que estamos calculando la puntuacion social
                    factor = G[G.nodes[predecessor]['data']][G.nodes[node]['data']]['factor']
                    factors_level_final.append(factor)
                    # Calculamos la puntuacion social y la asociamos al nodo
                    score_social_final = self.scoreSocial(factors_level_final,scores_level_final,score_node)
                    G.nodes[node]['score_social'] = score_social_final

          # Por ultimo, recorremos todos los observables y cuando el observable sea igual al nodo, obtenemos sus etiquetas y generamos una nueva con la puntuacion social asociada
          for o in observables:
              if G.nodes[node]['data'] == o.get('data') and G.nodes[node]['dataType'] not in descriptive_nodes:
                 tags = []
                 for tag in o.get('tags'):
                     tags.append(tag)
                 social = "Score_social: " + str(G.nodes[node]['score_social'])
                 tags.append(social)
                 data = json.dumps({"tags": tags})
                 req = THE_HIVE_URL + "/api/case/artifact/" + str(o['_id'])
                 headers = {'Authorization': 'Bearer {}'.format(THE_HIVE_API_KEY), 'Content-Type': 'application/json'}
                 response = requests.patch(req, headers=headers, data=data)
        
  
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
      data = json.dumps({"title": "Graph generated", "description": "Relations between observables of a case shown in a graphml", "type": "external", "source": "graph", "sourceRef": "GraphGenerated", "artifacts": [{"dataType": "file", "data": artifact, "message": "graph"}]})
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
  def scoreSocial(self, factors, scores, score_node):
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

      result = "{:.2f}".format(result)
      return result


if __name__ == '__main__':
   createGraph().run()