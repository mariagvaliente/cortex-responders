#!/usr/bin/env python3
# encoding: utf-8

## Libreria de cortexutils necesaria para usar las funciones de responder.
from cortexutils.responder import Responder

class scoreDecay(Responder):

    def __init__(self):
        Responder.__init__(self)

    ## Funcion run que ejecuta todo el procedimiento
    def run(self):
        Responder.run(self)
        ## Sacamos el valor del data que se va a utilizar en el responder (los datos de un caso,de un artifact, alerta...)
        name = self.get_param('data', None, 'data')
        print(name)
        ## Que el script haga sus cosas...
        .
        .
        .
        .
        ## Si el responder ha fallado por alguna razon (en este ejemplo la request devuelve
        ## un mensaje de fallo). Tendremos que terminar la ejecucion de la función llamando a
        ## self.error
        if "There was an error when adding the alert!" in str(query2.content):
            self.error('No se pudo crear la alerta')
        else:
            ## en caso contrario, devolveremos el report con el mensaje que queramos
            self.report({'message': 'Alerta añadida a Dnslytics'})

    ## Devolvemos una lista de operaciones generandolos con la funcion build_operation
    def operations(self, raw):
        print(raw)
        #return [self.build_operation('AddTagToArtifact', tag='mail sent')]


## Funcion que crea una instancia del objeto ejemploresponder y llama a su funcion run
if __name__ == '__main__':
    scoreDecay().run()