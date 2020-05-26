#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder
from datetime import datetime

from dateutil.parser import parse

class scoreDecay(Responder):

  def __init__(self):
      Responder.__init__(self)
      
  def run(self):
      Responder.run(self)
      name = self.get_param('data', None, 'data')
      # Extraemos los reports
      reports = name.get('reports')
      if reports != None:
        # Extraemos el tipo de dato de entrada
        dataType = name.get('dataType')
        # Obtenemos la fecha actual
        now = datetime.now()
        # Diccionario para almacenar los resultados de la funcion de decaimiento
        results = {}
        # Inicializamos la variable score_aggregated donde se va a guardar el valor de la puntuacion agregada por las distintas fuentes
        score_aggregated = 0.0
        # Recorremos cada analizador
        for analyzer in reports.keys():
            # Lista para almacenar las puntuaciones base del observable proporcionadas por cada fuente
            scores = []
            # Lista para almacenar la diferencia existente entre la fecha actual y última fecha en la que fue visto el observable segun cada fuente
            deltas = []
            # Lista para almacenar el nombre de los analizadores
            analyzers = []
            # Lista para almacenar las puntuaciones tras el decaimiento
            scores_decay = []
            
            analyzers.append(analyzer)
            report = reports[analyzer]
            taxonomies = report.get('taxonomies')
            if taxonomies != None:
            # A continuacion, para cada observable sacamos las taxonomias de cada analizador lanzado
               for taxonomy in taxonomies:
                   if taxonomy != None:
                       #   Extraemos el score 
                       if taxonomy.get('predicate') == 'Score':
                          scores.append(taxonomy.get('value'))
                       #   Extraemos la fecha en la que fue visto por ultima vez y calculamos la diferencia que existe entre las fecha actual y la fecha en la que fue visto por ultima vez (delta)
                       if taxonomy.get('predicate') == 'Last_seen':
                          date_last_seen = taxonomy.get('value')
                          datetime_max = parse(date_last_seen).replace(tzinfo=None)
                          delta = str((now - datetime_max).days)
                          # Guardamos las deltas en una lista (deltas)
                          deltas.append(delta)
                       print("Diferencia de fechas en dias:" + str(deltas))
                       print("Puntuaciones base:" + str(scores))
                       # Llamamos a la funcion timeDecay para calcular el decaimiento de la puntuacion pasando como parametro la lista con las deltas, la lista de scores y el dataType de la entrada
                       scores_decay = self.timeDecay(deltas, scores, dataType)
                       for a,s in zip(analyzers, scores_decay):
                           results[a] = str(s)
                           
            # Si tenemos puntuaciones de decaimiento entonces podemos calcular la puntuacion agregada
            if len(scores_decay) != 0:
               # Llamamos a la funcion aggregationFunction para calcular la puntuación agregada por todas las fuentes
               score_aggregated = self.aggregationFunction(results, dataType)
        # Diccionario para devolver la respuesta en el report
        records = {"score_aggregation": str(score_aggregated)}
      # Si no hay reports entonces asumimos que la score agregada es 0
      else:
        records = {"score_aggregation": "0.0"}
      self.report(records)
    
  # Funcion para calcular el decaimiento con el tiempo de las puntuaciones base
  # Recibe como parametro las listas deltas (con la diferencia de fechas en dias de cada analizador), la lista scores (con las puntuaciones base de cada analizador) y el tipo de dato de entrada
  # Devuelve una lista con las puntuaciones del observable una vez aplicado el decaimiento (scores_decay)
    
  def timeDecay(self, deltas, scores, dataType):
      # Lista para almacenar las puntuaciones nuevas del observable después de aplicar el decaimiento en el tiempo
      scores_decay = []
      # Tiempo de expiracion en dias: 60 dias para hashes y 30 dias para ip/dominio/url
      if dataType == "hash":
          end_time = 60
      else:
          end_time = 30
      # Tasa de decaimiento: 0.5
      decay_speed = 0.3
      # Lista para almacenar los resultados de la funcion
      results = []
      # Para cada una de las deltas calculamos la puntuacion de decaimiento teniendo en cuenta la puntuacion inicial (lista scores)
      for delta in deltas:
          time = (int(delta) / end_time)
          decay_time = pow(time, 1 / decay_speed)
          function = max(0, 1 - decay_time)
          results.append(function)
      for num1, num2 in zip(scores, results):
          scores_decay.append(float(num1) * num2)
      print("Puntuaciones despues del decaimiento:" + str(scores_decay))
      return scores_decay
      
  # Funcion para calcular la puntuacion agregada por todas las fuentes
  # Recibe como parametro las lista con los resultados obtenidos tras calcular la puntuacion teniendo en cuenta el decaimiento y el tipo de dato de entrada
  # Devuelve la puntuacion final del observable teniendo en cuenta todas las puntuaciones de todas las fuentes y el peso de cada una de ellas
  
  def aggregationFunction(self, results, dataType):
      # Lista para almacenar los pesos de cada analizador o fuente
      weights = []
      # Lista para almacenar las puntuaciones tras el decaimiento de cada analizador o fuente
      scores = []
      # Lista para almacenar el producto de cada uno de los valores de las listas anteriores
      scores_weight = []
      # Asignacion de pesos segun el tipo de dato de entrada y la fuente
      if dataType == "domain":
         for analyzer in results.keys():
             if analyzer == "Autofocus_Search_IOC_1_0":
                weight_AF = 0.4
                score_AF = float(results[analyzer])
                weights.append(weight_AF)
                scores.append(score_AF)
             if analyzer == "HybridAnalysis_1_0":
                weight_HB = 0.6
                score_HB = float(results[analyzer])
                weights.append(weight_HB)
                scores.append(score_HB)
      elif dataType == "ip":
         for analyzer in results.keys():
             if analyzer == "Autofocus_Search_IOC_1_0":
                weight_AF = 0.3
                score_AF = float(results[analyzer])
                weights.append(weight_AF)
                scores.append(score_AF)
             if analyzer == "HybridAnalysis_1_0":
                weight_HB = 0.5
                score_HB = float(results[analyzer])
                weights.append(weight_HB)
                scores.append(score_HB)
             if analyzer == "GreyNoise_2_3":
                weight_GN = 0.2
                score_GN = float(results[analyzer])
                weights.append(weight_GN)
                scores.append(score_GN)
      elif dataType == "url":
         for analyzer in results.keys():
             if analyzer == "Urlscan_search_1_0":
                weight_URL = 0.5
                score_URL = float(results[analyzer])
                weights.append(weight_URL)
                scores.append(score_URL)
             if analyzer == "VirusTotal_GetReport_3_1":
                weight_VT = 0.5
                score_VT = float(results[analyzer])
                weights.append(weight_VT)
                scores.append(score_VT)
      elif dataType == "hash":
         for analyzer in results.keys():
             if analyzer == "Autofocus_Search_Hash_1_0":
                weight_AF = 0.4
                score_AF = float(results[analyzer])
                weights.append(weight_AF)
                scores.append(score_AF)
             if analyzer == "HybridAnalysis_1_0":
                weight_HB = 0.2
                score_HB = float(results[analyzer])
                weights.append(weight_HB)
                scores.append(score_HB)
             if analyzer == "VirusTotal_GetReport_3_1":
                weight_VT = 0.4
                score_VT = float(results[analyzer])
                weights.append(weight_VT)
                scores.append(score_VT)
      # Calculamos el producto de cada una de las scores por los pesos correspondientes
      for num1, num2 in zip(scores, weights):
          scores_weight.append(num1 * num2)
      # Suma de todos los scores*weight de cada una de las fuentes en las que se ha analizado el observable
      sum_scores_weight = 0
      for f in scores_weight:
          sum_scores_weight = sum_scores_weight + f
      # Suma de todos los pesos de cada una de las fuentes en las que se ha analizado el observable
      sum_weights = 0
      for w in weights:
          sum_weights = sum_weights + w
          
      # Calculamos la funcion de agregacion dividiendo las sumas anteriores
      score_aggregated = sum_scores_weight/sum_weights
      
      return score_aggregated
  

  def operations(self,raw):
      operations = []
      print(raw)
      for r in raw.keys():
        operations.append(self.build_operation('AddTagToArtifact', tag='Score_aggregated:' + raw[r]))
      return operations

if __name__ == '__main__':
   scoreDecay().run()
