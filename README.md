# Memecoin Radar 24/7

Radar autónomo para Telegram que descubre tokens recientes con DexScreener, aplica filtros de mercado, audita riesgos básicos y publica una tarjeta visual con botones de acción.

## Qué analiza

- Pares de Solana por defecto y Base de forma opcional.
- Antigüedad entre 5 minutos y 24 horas.
- Liquidez superior a 10.000 USD.
- Volumen superior a 30.000 USD en una hora, o aceleración clara en cinco minutos.
- Más compras que ventas durante la última hora.
- Puntuación de momentum mínima de 60 sobre 100.
- Además exige más de 5.000 USD en cinco minutos y una señal reciente: subida de precio del 8% o volumen al triple del ritmo medio de los 55 minutos anteriores. La comparación de volumen requiere una hora de antigüedad del par.
- La tarjeta usa el logo del par cuando DexScreener lo facilita. El contrato completo aparece en un bloque propio del pie de foto y en el botón de copia.
- Informe de RugCheck en Solana y GoPlus en Base.

El filtro reduce ruido, pero no demuestra que un token sea seguro ni predice su rendimiento.

## Configuración

1. Añade el bot como administrador del canal con permiso para publicar.
2. Crea los secretos `TELEGRAM_TOKEN` y `CHAT_ID` en GitHub Actions.
3. Sube todos los archivos, incluida `.github/workflows/main.yml`.
4. Ejecuta manualmente el workflow en modo `test`.
5. Ejecuta `dry-run` para revisar candidatos y después `live` para una pasada real.

El cron usa el modo `live` cada cinco minutos. Las ejecuciones se serializan y el historial se reserva antes de publicar para reducir duplicados.

## Variables opcionales

- `ENABLE_BASE=true` activa Base.
- `CHANNEL_USERNAME=alias_sin_arroba` añade el enlace público al pie si `CHAT_ID` es un ID numérico.

## Operación

`sent_tokens.json` contiene tokens reservados o enviados. Una entrada `reserved` aparece cuando el historial se guardó antes de contactar con Telegram. Si una publicación queda con resultado incierto, la reserva permanece para impedir un posible duplicado.

GitHub puede retrasar ejecuciones programadas y desactivar cron en repositorios públicos sin actividad prolongada. Las APIs y sus condiciones también pueden cambiar. Conviene revisar la pestaña Actions periódicamente.

## Public accountability

Every confirmed signal stores its original price and liquidity. The radar observes the market again at approximately 1 hour, 6 hours and 24 hours, then publishes a `THE RECEIPT` update after 24 hours. On Sundays it publishes a seven-day scorecard when at least three outcomes are available. Positive and negative results remain in the same public record.
