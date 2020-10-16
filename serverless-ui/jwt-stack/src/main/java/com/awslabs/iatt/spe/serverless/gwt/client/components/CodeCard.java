package com.awslabs.iatt.spe.serverless.gwt.client.components;

import com.awslabs.iatt.spe.serverless.gwt.client.BrowserHelper;
import elemental2.dom.HTMLDivElement;
import elemental2.dom.HTMLPreElement;
import org.dominokit.domino.ui.cards.Card;
import org.dominokit.domino.ui.icons.Icons;
import org.dominokit.domino.ui.utils.BaseDominoElement;
import org.dominokit.domino.ui.utils.DominoElement;
import org.jboss.elemento.Elements;

public class CodeCard extends BaseDominoElement<HTMLDivElement, CodeCard> {
    private final HTMLPreElement codeBlock = Elements.pre().css("prettyprint").element();
    private final Card card = Card.create("Source Code")
            .setCollapsible()
            .hide()
            .appendChild(codeBlock);
    private String code;

    public CodeCard() {
        card.addHeaderAction(Icons.ALL.content_copy()
                .setTooltip("Copy code"), evt -> BrowserHelper.copyThis(code));

        init(this);
    }

    public static CodeCard createCodeCard(String code) {
        CodeCard codeCard = new CodeCard();
        DominoElement.of(codeCard.codeBlock)
                .clearElement()
                .setInnerHtml(code);
        codeCard.code = code;
        return codeCard;
    }

    public CodeCard setCode(String code) {
        DominoElement.of(this.codeBlock).setInnerHtml(code);
        this.code = code;
        return this;
    }

    public CodeCard setTitle(String title) {
        card.setTitle(title);
        return this;
    }

    public CodeCard setDescription(String description) {
        card.setDescription(description);
        return this;
    }

    public Card getCard() {
        return card;
    }

    @Override
    public HTMLDivElement element() {
        return card.element();
    }
}
