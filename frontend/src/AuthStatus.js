import * as React from 'react';
import { useAuth } from './auth';
import { Button } from '@mui/material';
import DevicesModal from './DeviceModal';

export default function AuthStatus() {
  const { user, signOut, expireToken } = useAuth();
  if (!user?.token || !user?.email) {
    return <p>You are not logged in.</p>;
  }
  return (
    <p>
      Welcome {user.email}!{' '}
      <Button onClick={signOut}>
        Sign out
      </Button>
      <Button onClick={expireToken}>
        Simulate Token Expiration
      </Button>
      <Button onClick={expireToken}>
        Simulate Token Expiration
      </Button>
      <DevicesModal  />
    </p>
  );
}
