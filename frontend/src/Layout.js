import * as React from 'react';
import { useAuth } from './auth';
import { Link, Outlet } from 'react-router-dom';
import AuthStatus from './AuthStatus';

export  default function Layout() {
  const { user } = useAuth();
  return (
    <div>
      <AuthStatus />
      <ul>
        {!user?.token ? (
          <li>
            <Link to="/create-account">Create account</Link>
          </li>
        ) : null}
        <li>
          <Link to="/stream">Stream</Link>
        </li>
      </ul>
      <Outlet />
    </div>
  );
}