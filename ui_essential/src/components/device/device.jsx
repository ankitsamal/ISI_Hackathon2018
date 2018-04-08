import React from 'react';
import s from './device.scss';
import Packet from './packet/packet.jsx';
import c from 'classnames';

class Device extends React.Component {
  handleClick = event => {
    this.setState({ expanded: !this.state.expanded });
  }
  state = {
    expanded: false
  }
  render() {
    return (
      <div className={s.device} onClick={e => this.handleClick(e)}>
        <div className={s.info}>
          <table>
            <tbody>
              <tr className={this.props.org?null:s.invisible}>
                <th> Vendor: </th>
                <td> { this.props.org } </td>
              </tr>
              <tr>
                <th> MAC Address: </th>
                <td> { this.props.mac || 'Unidentified Device' } </td>
              </tr>
              <tr 
                className={this.props.host.length?null:s.invisible}
              >
                <th> Host: </th>
                <td> { this.props.host?this.props.host.toString().replace(/,/g,', '):null } </td>
              </tr>
              <tr 
                className={this.props.token.length?null:s.invisible}
              >
                <th> Token: </th>
                <td> { this.props.token?this.props.token.toString().replace(/,/g,', '):null } </td>
              </tr>
              <tr 
                className={this.props.serial.length?null:s.invisible}
              >
                <th> Serial: </th>
                <td> { this.props.serial?this.props.serial.toString().replace(/,/g,', '):null } </td>
              </tr>
              <tr 
                className={this.props.model.length?null:s.invisible}
              >
                <th> Model: </th>
                <td> { this.props.model?this.props.model.toString().replace(/,/g,', '):null } </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div className={
          c(s.packets,this.state.expanded?null:s.hidden)
        }>
          {
            this.props.packets.map((packet,i) => {
              return(
                <Packet
                  key={i}
                  ids={packet.id}
                  date={packet.date}
                  time={packet.time}
                  src_ip={packet.source_ip}
                  src_port={packet.source_port}
                  src_mac={this.props.mac}
                  dst_mac={packet.dest_mac}
                  dst_ip={packet.dest_ip}
                  dst_port={packet.dest_port}
                  protocol={packet.protocol}
                  good={packet.good_packet}
                  allow={packet.allowed}
                  rule={packet.rule}
                />
              );
            })
          }
        </div>
      </div>
    );
  }
}

const mapStateToProps = state => ({
  devices: state.devices
});

export default Device;