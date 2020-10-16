package com.awslabs.iatt.spe.serverless.gwt.client.cards;

import com.awslabs.iatt.spe.serverless.gwt.client.components.CodeCard;
import com.awslabs.iatt.spe.serverless.gwt.shared.JwtResponse;
import elemental2.dom.HTMLDivElement;
import org.dominokit.domino.api.client.annotations.UiView;
import org.dominokit.domino.ui.cards.Card;
import org.dominokit.domino.ui.utils.BaseDominoElement;
import org.dominokit.domino.view.BaseElementView;

@UiView(presentable = InspectProxy.class)
public class InspectViewImpl extends BaseElementView<HTMLDivElement> implements InspectView {
    private CodeCard decodedJwtCodeCard;
    private InspectUiHandlers uiHandlers;

    @Override
    protected HTMLDivElement init() {
        decodedJwtCodeCard = CodeCard.createCodeCard("")
                .setTitle("Decoded JWT data")
                .apply(BaseDominoElement::show);

        invalidate();

        return Card.create("Inspect", "You can inspect JWTs on this tab")
                .appendChild(decodedJwtCodeCard)
                .element();
    }

    @Override
    public void onJwtChanged(JwtResponse jwtResponse) {
        decodedJwtCodeCard.setCode(jwtResponse.decodedJwt);
    }

    @Override
    public void onInvalidatedEvent() {
        invalidate();
    }

    private void invalidate() {
        decodedJwtCodeCard.setCode("Not generated yet");
    }

    @Override
    public void setUiHandlers(InspectUiHandlers uiHandlers) {
        this.uiHandlers = uiHandlers;
    }
}