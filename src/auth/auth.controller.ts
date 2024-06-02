import { Controller, Get, Req, Res, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthGuard } from '@nestjs/passport';
import { Request, Response } from 'express';
import { GoogleUserInterface } from './interfaces/google_user.interface';

@Controller('api/v1/auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth(): Promise<void> {}

  @Get('/google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthRedirect(@Req() req: Request, @Res() res: Response) {
    if (!req.user) {
      return res.send('No user from google');
    }
    const accessToken = await this.authService.authenticateGoogleUser(
      req.user as GoogleUserInterface,
    );

    res.redirect(req.user['redirectUrl'] + '?accessToken=' + accessToken);
  }
}
