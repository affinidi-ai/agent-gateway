import {test as teardown} from '@playwright/test';
import {GatewayApi} from '../../helpers/gateway-api';
import {newContext} from '../../helpers/oidc-live/hydra';
import {cleanGateway, destroyWorld} from '../../helpers/oidc-live/world';

teardown('remove everything the suite created', async () => {
    const hydra = await newContext();
    const api = await GatewayApi.connect();
    try {
        await cleanGateway(api);
        await destroyWorld(hydra);
    } finally {
        await api.dispose();
        await hydra.dispose();
    }
});
