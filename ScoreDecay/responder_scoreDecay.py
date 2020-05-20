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
      reports = name.get('reports')
      print(reports)
      # Lista para almacenar las puntuaciones base del observable proporcionadas por cada fuente
      scores = []
      # Lista para almacenar la diferencia existente entre la primera y última fecha en la que fue visto el observable segun cada fuente
      deltas = []
      # Obtenemos la fecha actual
      now = datetime.now()
      # Lista para almacenar el nombre de los analizadores
      analyzers = []
      # Diccionario para devolver la respuesta en el report (formato analizador: score_decay)
      records = {}
      for analyzer in reports.keys():
          analyzers.append(analyzer)
          report = reports[analyzer]
          taxonomies = report.get('taxonomies')
          print(taxonomies)
          if taxonomies != None:
             for taxonomy in taxonomies:
                 if taxonomy.get('predicate') == 'Score':
                    scores.append(taxonomy.get('value'))
                 if taxonomy.get('predicate') == 'Last_seen':
                    date_last_seen = taxonomy.get('value')
                    datetime_max = parse(date_last_seen).replace(tzinfo=None)
          delta = str((now - datetime_max).days)
          deltas.append(delta)
          print("Diferencia de fechas en dias:" + str(deltas))
          print("Puntuaciones base:" + str(scores))
          # Lista para almacenar las puntuaciones nuevas del observable después de aplicar el decaimiento en el tiempo
          scores_decay = []
          # Tiempo de expiracion en dias: 60 dias para hashes y 30 dias para ip/dominio/url
          if self.data_type == "hash":
              end_time = 60
          else:
              end_time = 30
          # Tasa de decaimiento: 0.5
          decay_speed = 0.4
          # Lista para guardar los resultados de la funcion
          results = []
          for delta in deltas:
              time = float(int(delta) / end_time)
              decay_time = pow(time, 1 / decay_speed)
              function = max(0, 1 - decay_time)
              results.append(function)
          for num1, num2 in zip(scores, results):
              scores_decay.append(float(num1) * num2)
          print("Puntuaciones despues del decaimiento:" + str(scores_decay))
      print(analyzers)
      for a,s in zip(analyzers, scores_decay):
          records[a] = str(s)

      self.report(records)
  

  def operations(self,raw):
      operations = []
      print(raw)
      for r in raw.keys():
        operations.append(self.build_operation('AddTagToArtifact', tag=r + ':Score_decay:' + str(raw[r])))
      return operations

if __name__ == '__main__':
   scoreDecay().run()
