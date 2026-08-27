import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';

import { AppModule } from './app.module.js';
import type { ConfigAdmin } from './config.js';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // `<ConfigAdmin, true>` : le second parametre dit que la config est VALIDEE,
  // ce qui fait rendre `number` a `get` au lieu de `number | undefined`.
  const config = app.get<ConfigService<ConfigAdmin, true>>(ConfigService);

  await app.listen(config.get('ADMIN_PORT', { infer: true }));
}

void bootstrap();
