import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { LocalStrategy } from './strategy/local.strategy';
import { UserRepository } from '../users/repositories/user.repository';
import { JwtModule } from '@nestjs/jwt';
import { JwtAccessStrategy } from './strategy/jwt-access.strategy';
import { GoogleStrategy } from './strategy/google.strategy';

@Module({
  imports: [JwtModule],
  controllers: [AuthController],
  providers: [
    AuthService,
    LocalStrategy,
    JwtAccessStrategy,
    UserRepository,
    GoogleStrategy,
  ],
})
export class AuthModule {}
