#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder
from datetime import datetime

from dateutil.parser import parse

class createGraph(Responder):

  def __init__(self):
      Responder.__init__(self)
      

  def run(self):
      Responder.run(self)
      name = self.get_param('data', None, 'data')
      print(name)
  
#  def operations(self,raw):
#      operations = []
#      print(raw)
#      for r in raw.keys():
#        operations.append(self.build_operation('AddTagToArtifact', tag=r + ':Score_decay:' + str(raw[r])))
#      return operations

if __name__ == '__main__':
   createGraph().run()