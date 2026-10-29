import {test as setup} from '@playwright/test';
import {GatewayApi} from '../../helpers/gateway-api';
import {newContext} from '../../helpers/oidc-live/hydra';
import {cleanGateway, createWorld} from '../../helpers/oidc-live/world';

setup('create the Ory side and clear earlier gateway state', async () => {
    const hydra = await newContext();
    const api = await GatewayApi.connect();
    try {
        await cleanGateway(api);
        await createWorld(hydra);
    } finally {
        await api.dispose();
        await hydra.dispose();
    }
});
