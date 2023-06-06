import * as React from 'react';
import { useAuth } from './auth';

export default function AuthStatus() {
  const { user, signOut, expireToken } = useAuth();
  if (!user?.token || !user?.email) {
    return <p>You are not logged in.</p>;
  }
  return (
    <p>
      Welcome {user.email}!{' '}
      <button onClick={signOut}>
        Sign out
      </button>
      <button onClick={expireToken}>
        Expire Token
      </button>
    </p>
  );
}
