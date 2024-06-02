export interface GoogleUserInterface {
  email: string;
  firstName: string;
  lastName: string;
  picture: string;
  accessToken: string;
  redirectUrl?: string | null;
}
