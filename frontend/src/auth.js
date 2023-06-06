import * as React from 'react';
import { useNavigate } from 'react-router-dom';
import { ROUTES } from './constants';

const AuthContext = React.createContext();

export function AuthProvider({ children }) {
  const navigate = useNavigate();
  const [user, setUser] = React.useState(() => {
    const userProfile = localStorage.getItem('userProfile');
    return userProfile ? JSON.parse(userProfile) : null;
  });

  const signIn = async (payload, errorCallback) => {
    try {
      const response = await fetch(ROUTES.login, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (response.ok) {
        const data = await response.json();
        localStorage.setItem('userProfile', JSON.stringify(data));
        setUser(data);
        navigate(-1);
      } else {
        throw new Error('Invalid email or password');
      }
    } catch (err) {
      console.error(err);
      if (errorCallback) errorCallback(err.message);
    }
  };

  const expireToken = async (errorCallback) => {
    try {
      await fetch(ROUTES.signOut, {
        method: 'POST',
        headers: { Authorization: `Bearer ${user?.token}` },
      });
      console.log('Token has been blacklisted');
    } catch (err) {
      console.error('Error blacklisting token', err);
      if (errorCallback) errorCallback(err.message);
    }
  };

  const signOut = async (errorCallback) => {
    await expireToken(errorCallback);
    localStorage.removeItem('userProfile');
    setUser(null);
    navigate('/');
  };

  const createAccount = async (payload, errorCallback) => {
    try {
      const response = await fetch(ROUTES.createAccount, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (response.ok) {
        const data = await response.json();
        localStorage.setItem('userProfile', JSON.stringify(data));
        setUser(data);
        navigate(-1);
      } else {
        throw new Error('Failed to create account');
      }
    } catch (err) {
      if (errorCallback) errorCallback(err.message);
      console.error(err);
    }
  };

  const value = { user, signIn, signOut, expireToken, createAccount };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  return React.useContext(AuthContext);
}

export function RequireAuth({ children, FallbackComponent }) {
  const { user } = useAuth();
  return user?.token ? children : <FallbackComponent />;
}
