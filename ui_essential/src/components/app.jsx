import React from 'react';
import s from './app.scss';
import Device from './device/device.jsx';
import axios from 'axios';
import io from 'socket.io-client';

class App extends React.Component {
  constructor(props) {
    super(props);
  }
  componentDidMount() {
    let host;
    location.hostname=='localhost' ? host=location.host : host=location.hostname;
    let socket = io.connect('http://' + location.hostname + ':8080');
    socket.on('connected', data => {
      console.log(data);
    });
    socket.on('post', packets => {
      if(Object.keys(packets)[0] == 'packets') packets = packets.packets;
      let newState = this.state;
      Object.keys(packets).forEach(device => {
        if(newState.packets[device])
          newState.packets[device].packets.concat(device.packets);
        else
          newState.packets[device] = packets[device];
      });
      this.setState(newState);
    })
    this.setState({ ...this.state, socket: socket });
  }
  state = {
    packets: {},
    socket: null
  }
  render() {
    return (
      <div className={s.app}>
        <div className={s.devices}>
          <div className={s.title}>Devices</div>
          {
            Object.keys(this.state.packets).map((key,i) => {
              return(
                <Device
                  key={ i }
                  mac={ key || null }
                  org={ this.state.packets[key].org || null }
                  host={ this.state.packets[key].host || [] }
                  packets={ this.state.packets[key].packets || []}
                  token={ this.state.packets[key].token || []}
                  serial={ this.state.packets[key].serialNumber || []}
                  model={ this.state.packets[key].model || []}
                />
              );
            })
          }
        </div>
      </div>
    );
  }
}

export default App;