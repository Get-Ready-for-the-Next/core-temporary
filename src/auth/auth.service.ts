import { ConflictException, Injectable } from '@nestjs/common';
import { UserRepository } from '../users/repositories/user.repository';
import {
  hashPlainText,
  randomString,
} from '../common/constants/encryption.constant';
import { User } from '../users/entities/user.entity';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { AuthenticatedUser } from './interfaces/auth.interface';
import { GoogleUserInterface } from './interfaces/google_user.interface';

@Injectable()
export class AuthService {
  constructor(
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
    private readonly userRepository: UserRepository,
  ) {}

  async authenticateGoogleUser(googleUser: GoogleUserInterface) {
    const isUserRegistered = await this.userRepository.isEmailRegistered(
      googleUser.email,
    );

    let user = null;

    if (!isUserRegistered) {
      await this.signUp(
        googleUser.email,
        randomString(20),
        `${googleUser.lastName}${googleUser.firstName}`,
        googleUser.picture,
      );
    }

    user = await this.userRepository.findUserByEmail(googleUser.email);
    return this.generateAccessToken(user);
  }

  generateAccessToken(user: User): string {
    return this.jwtService.sign(
      { user: this.extractPayloadFromUser(user) },
      {
        secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET'),
        expiresIn: this.configService.get('JWT_ACCESS_TOKEN_EXPIRATION_TIME'),
      },
    );
  }

  async signUp(
    email: string,
    password: string,
    nickname: string,
    picture: string | null,
  ): Promise<AuthenticatedUser> {
    const emailExists = await this.userRepository.isEmailRegistered(email);

    if (emailExists) {
      throw new ConflictException(
        'This email is already registered. Please use another email.',
      );
    }

    const hashedPassword = await hashPlainText(password);

    const user = await this.userRepository.signUp(
      email,
      hashedPassword,
      nickname,
      picture,
    );

    return this.extractPayloadFromUser(user);
  }

  private extractPayloadFromUser(user: User): AuthenticatedUser {
    return {
      id: user.id,
      nickname: user.nickname,
      email: user.email,
      picture: user.picture,
    };
  }
}
