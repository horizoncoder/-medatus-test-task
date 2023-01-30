import {
    Body,
    Controller,
    Post,
    UseGuards,
    Request,
    HttpCode,
    UsePipes,
    ValidationPipe,
    BadRequestException,
    HttpException,
    HttpStatus, Session,
} from '@nestjs/common';

import * as bcrypt from 'bcrypt';
import { AuthenticatedGuard } from 'src/auth/authenticated.guard';
import { LocalAuthGuard } from 'src/auth/local.auth.guard';
import { UsersService } from './users.service';
import { RegisterDto } from './dto/register.dto';
import * as zxcvbn from 'zxcvbn';
import { resetPassword } from './dto/resetPassword.dto';
@Controller('user')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post('/register')
  @HttpCode(201)
  @UsePipes(ValidationPipe)
  async register(
    @Body('password') password: string,
    @Body('username') userName: string,
    @Body() message: RegisterDto,
  ) {
    try {
      const checkPassword = zxcvbn(password).feedback;
      if (checkPassword.warning.length > 0) {
        new BadRequestException(checkPassword);
      }
      const hashedPassword = await bcrypt.hash(password, 10);

      await this.usersService.insertUser(userName, hashedPassword);
      return {
        message,
      };
    } catch (error) {
      throw new HttpException(
        {
          message: error.message || 'Oops, unexpected error',
        },
        error.status || HttpStatus.FORBIDDEN,
      );
    }
  }

  @UseGuards(LocalAuthGuard)
  @HttpCode(200)
  @Post('/login')
  login(): any {
    try {
      return { message: 'User logged in' };
    } catch (error) {
      throw new HttpException(
        {
          message: error.message || 'Oops, unexpected error',
        },
        error.status || HttpStatus.FORBIDDEN,
      );
    }
  }

  @UseGuards(AuthenticatedGuard)
  @Post('/reset-password')
  @HttpCode(201)
  async resetUserPassword(
    @Request() req,
    @Body('oldPassword') oldPassword: string,
    @Body('newPassword') newPassword: string,
    @Body() message: resetPassword,
    @Session() session: Record<string, any>,
  ): Promise<any> {
    try {
      const checkPassword = zxcvbn(newPassword).feedback;
      if (checkPassword.warning.length > 0) {
        new BadRequestException(checkPassword);
      }
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      const result = await this.usersService.restPassword(
        session.passport.user.userId,
        oldPassword,
        hashedPassword,
      );
      if (result) {
        session.destroy();
        return {
          message,
        };
      }
    } catch (error) {
      throw new HttpException(
        {
          message: error.message || 'Oops, unexpected error',
        },
        error.status || HttpStatus.FORBIDDEN,
      );
    }
  }
}
