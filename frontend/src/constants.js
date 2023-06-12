const API_END_POINT = 'http://localhost:8080';

export const ROUTES = {
  login: `${API_END_POINT}/api/login`,
  signOut: `${API_END_POINT}/api/sign-out`,
  createAccount: `${API_END_POINT}/api/create-account`,
  devices: `${API_END_POINT}/api/user/devices`,
  videoStream: `${API_END_POINT}/stream/segment.m3u8`,
};
