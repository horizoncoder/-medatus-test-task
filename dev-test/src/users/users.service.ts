import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './users.model';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
  constructor(@InjectModel('user') private readonly userModel: Model<User>) {}

  async insertUser(userName: string, password: string) {
    if (await this.getUser(userName)) {
      throw new BadRequestException('user with that email already exists');
    }
    const username = userName.toLowerCase();
    const newUser = new this.userModel({
      username,
      password,
    });
    await newUser.save();
    return newUser;
  }
  async getUser(userName: string) {
    const username = userName.toLowerCase();
    return this.userModel.findOne({ username });
  }
  async restPassword(userId: string, oldPassword: string, newPassword: string) {
    const user = await this.userModel.findById({ _id: userId });
    const passwordValid = await bcrypt.compare(oldPassword, user.password);
    if (!passwordValid) {
      throw new BadRequestException('Old password is wrong');
    }
    if (userId === user._id.toString()) {
      await this.userModel.updateOne(
        { _id: userId },
        { password: newPassword },
      );
    }
    return true;
  }
}
