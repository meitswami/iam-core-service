import { Controller, Get, UseGuards } from '@nestjs/common';
import { AppService } from './app.service';
import { AnyAuthGuard } from './iam/guards/any-auth.guard';
import { RolesGuard } from './iam/guards/roles.guard';
import { Roles } from './iam/decorators/roles.decorator';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  @UseGuards(AnyAuthGuard, RolesGuard)
  @Roles('Admin', 'SuperAdmin')
  getHello(): string {
    return this.appService.getHello();
  }
}
