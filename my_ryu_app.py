from ryu.controller import Controller
from ryu.lib import hub

class MyRyuApp(Controller):
    def __init__(self, *args, **kwargs):
        super(MyRyuApp, self).__init__(*args, **kwargs)
        hub.spawn(self._monitor)

    def _monitor(self):
        print("Ryu controller is running!")

if __name__ == '__main__':
    app = MyRyuApp()
    app.run()
