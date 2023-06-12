import React, { useState, useEffect } from 'react';
import { Modal, Button, List, ListItem, ListItemText } from '@mui/material';
import { useAuth } from './auth';
import { ROUTES } from './constants';

const DevicesModal = () => {
  const [open, setOpen] = useState(false);
  const [devices, setDevices] = useState([]);

  const auth = useAuth();
  const token = auth.user?.token; // Retrieve the authentication token from the user's session or storage
  const removeDeviceOptions = {
    method: 'DELETE',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
  };

  const handleClose = () => {
    setOpen(false);
  };

  const handleOpen = () => {
    setOpen(true);
  };

  const fetchDevices = () => {
    fetch(ROUTES.devices, { headers: removeDeviceOptions.headers })
      .then((response) => response.json())
      .then((data) => setDevices(data.devices))
      .catch((error) => console.error(error));
  };

  useEffect(() => {
    fetchDevices();
  }, []);

  const handleRemoveDevice = (device) => {
    fetch(`${ROUTES.devices}/${device.ID}`, removeDeviceOptions)
      .then((response) => response.json())
      .then((data) => {
        if (data.success) {
          if (device.Token === auth.user.token) {
            auth.signOut();
          }
          setDevices(devices.filter((d) => device.ID !== d.ID));
        } else {
          console.error(data.message);
        }
      })
      .catch((error) => console.error(error));
  };

  return (
    <>
      <Button variant="contained" onClick={handleOpen}>
        Open Devices
      </Button>
      <Modal open={open} onClose={handleClose}>
        <div style={{ backgroundColor: 'white' }}>
          <h2>Devices</h2>
          <List>
            {devices.map((device) => (
              <ListItem key={device.id}>
                <ListItemText primary={device.DeviceName} />
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={() => handleRemoveDevice(device)}
                >
                  Remove
                </Button>
              </ListItem>
            ))}
          </List>
        </div>
      </Modal>
    </>
  );
};

export default DevicesModal;
