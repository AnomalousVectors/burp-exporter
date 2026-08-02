package ai.anomalousvectors.tools.burp.ui.text;

import static org.assertj.core.api.Assertions.assertThat;

import java.awt.Dimension;
import java.awt.Point;
import java.awt.Rectangle;

import javax.swing.JPanel;
import javax.swing.JToolTip;
import javax.swing.PopupFactory;
import javax.swing.ToolTipManager;

import org.junit.jupiter.api.Test;

class TooltipsWindowClampTest {

    @Test
    void clampToBounds_slidesLeftJustEnoughWhenOverflowingRightEdge() {
        Rectangle window = new Rectangle(100, 50, 400, 300);
        Dimension tip = new Dimension(180, 40);
        // Preferred X would place the tip past the right edge; slide left to fit.
        Point fitted = Tooltips.clampToBounds(window, 350, 80, tip, 4);
        assertThat(fitted.x).isEqualTo(100 + 400 - 180 - 4);
        assertThat(fitted.x).isGreaterThanOrEqualTo(window.x + 4);
        assertThat(fitted.x + tip.width).isLessThanOrEqualTo(window.x + window.width - 4);
        assertThat(fitted.y).isEqualTo(80);
    }

    @Test
    void clampToBounds_pinsWhenTipWiderThanWindow() {
        Rectangle window = new Rectangle(0, 0, 200, 200);
        Dimension tip = new Dimension(500, 40);
        Point fitted = Tooltips.clampToBounds(window, 50, 20, tip, 4);
        assertThat(fitted.x).isEqualTo(4);
        assertThat(fitted.y).isEqualTo(20);
    }

    @Test
    void constrainTipWidthToBounds_fitsLongHtmlInsideNarrowWindow() {
        JToolTip tip = Tooltips.createHtmlToolTip(new JPanel());
        tip.setTipText("<html>" + "long tooltip text ".repeat(30) + "</html>");

        Tooltips.constrainTipWidthToBounds(new Rectangle(0, 0, 200, 500), tip);

        assertThat(tip.getPreferredSize().width).isLessThanOrEqualTo(200 - 8);
    }

    @Test
    void sharedPopupFactory_installAndRestore_areIdempotent() {
        ToolTipManager manager = ToolTipManager.sharedInstance();
        int initialDelay = manager.getInitialDelay();
        int reshowDelay = manager.getReshowDelay();
        int dismissDelay = manager.getDismissDelay();
        Tooltips.restoreSharedPopupFactory();
        PopupFactory original = PopupFactory.getSharedInstance();
        try {
            Tooltips.configureSharedToolTipManager();
            PopupFactory installed = PopupFactory.getSharedInstance();
            assertThat(installed).isNotSameAs(original);

            Tooltips.configureSharedToolTipManager();
            assertThat(PopupFactory.getSharedInstance()).isSameAs(installed);

            Tooltips.restoreSharedPopupFactory();
            assertThat(PopupFactory.getSharedInstance()).isSameAs(original);
            Tooltips.restoreSharedPopupFactory();
            assertThat(PopupFactory.getSharedInstance()).isSameAs(original);
        } finally {
            Tooltips.restoreSharedPopupFactory();
            PopupFactory.setSharedInstance(original);
            manager.setInitialDelay(initialDelay);
            manager.setReshowDelay(reshowDelay);
            manager.setDismissDelay(dismissDelay);
        }
    }

    @Test
    void clampToBounds_keepsPreferredWhenFullyInside() {
        Rectangle window = new Rectangle(0, 0, 800, 600);
        Dimension tip = new Dimension(100, 40);
        Point fitted = Tooltips.clampToBounds(window, 120, 90, tip, 4);
        assertThat(fitted).isEqualTo(new Point(120, 90));
    }

    @Test
    void clampToBounds_doesNotJumpToFarLeftWhenNearRightEdge() {
        Rectangle window = new Rectangle(0, 0, 1000, 600);
        Dimension tip = new Dimension(300, 80);
        // Hover near the right side (e.g. Profile field); tip must stay near that side.
        Point fitted = Tooltips.clampToBounds(window, 850, 100, tip, 4);
        assertThat(fitted.x).isEqualTo(1000 - 300 - 4);
        assertThat(fitted.x).isGreaterThan(500);
    }

    @Test
    void placeBesideAvoiding_prefersBelowWhenBothBelowAndRightFit() {
        Rectangle window = new Rectangle(0, 0, 1000, 600);
        Rectangle menu = new Rectangle(100, 100, 180, 120);
        Dimension tip = new Dimension(300, 80);
        Point fitted = Tooltips.placeBesideAvoiding(window, menu, tip, 120);
        assertThat(fitted.y).isGreaterThanOrEqualTo(menu.y + menu.height);
        assertThat(new Rectangle(fitted.x, fitted.y, tip.width, tip.height).intersects(menu)).isFalse();
    }

    @Test
    void placeBesideAvoiding_usesRightWhenBelowAndAboveDoNotFit() {
        Rectangle window = new Rectangle(0, 0, 1000, 250);
        Rectangle menu = new Rectangle(100, 40, 180, 180);
        Dimension tip = new Dimension(200, 80);
        Point fitted = Tooltips.placeBesideAvoiding(window, menu, tip, 80);
        assertThat(fitted.x).isGreaterThanOrEqualTo(menu.x + menu.width);
        assertThat(new Rectangle(fitted.x, fitted.y, tip.width, tip.height).intersects(menu)).isFalse();
    }

    @Test
    void placeBesideAvoiding_prefersBelowWhenSidesTooNarrow() {
        Rectangle window = new Rectangle(0, 0, 500, 600);
        Rectangle menu = new Rectangle(40, 80, 420, 100);
        Dimension tip = new Dimension(360, 90);
        Point fitted = Tooltips.placeBesideAvoiding(window, menu, tip, 100);
        assertThat(fitted.y).isGreaterThanOrEqualTo(menu.y + menu.height);
        assertThat(new Rectangle(fitted.x, fitted.y, tip.width, tip.height).intersects(menu)).isFalse();
    }

    @Test
    void placeBesideAvoiding_prefersBelowEvenWhenRightHasPartialSpace() {
        // Narrow Config column: a few px to the right of the menu is not enough for the tip width.
        // Prefer below so the tip does not clamp back over the menu.
        Rectangle window = new Rectangle(0, 0, 480, 700);
        Rectangle menu = new Rectangle(20, 120, 400, 140);
        Dimension tip = new Dimension(360, 100);
        Point fitted = Tooltips.placeBesideAvoiding(window, menu, tip, 150);
        assertThat(fitted.y).isGreaterThanOrEqualTo(menu.y + menu.height);
        assertThat(new Rectangle(fitted.x, fitted.y, tip.width, tip.height).intersects(menu)).isFalse();
    }

    @Test
    void placeBesideAvoiding_doesNotReturnOverlappingPointWhenClampWouldSlideOverMenu() {
        Rectangle window = new Rectangle(0, 0, 420, 500);
        Rectangle menu = new Rectangle(10, 50, 400, 120);
        Dimension tip = new Dimension(380, 80);
        Point fitted = Tooltips.placeBesideAvoiding(window, menu, tip, 70);
        assertThat(new Rectangle(fitted.x, fitted.y, tip.width, tip.height).intersects(menu)).isFalse();
    }

    @Test
    void placeToRightOf_prefersRightWhenRightAndBelowBothFit() {
        Rectangle window = new Rectangle(0, 0, 1000, 600);
        Rectangle button = new Rectangle(40, 200, 120, 28);
        Dimension tip = new Dimension(300, 120);
        Point fitted = Tooltips.placeToRightOf(window, button, tip);
        assertThat(fitted.x).isGreaterThanOrEqualTo(button.x + button.width);
        assertThat(new Rectangle(fitted.x, fitted.y, tip.width, tip.height).intersects(button)).isFalse();
    }

    @Test
    void placeToRightOf_fallsBackLeftWhenRightDoesNotFit() {
        Rectangle window = new Rectangle(0, 0, 800, 600);
        Rectangle button = new Rectangle(500, 200, 120, 28);
        Dimension tip = new Dimension(280, 80);
        Point fitted = Tooltips.placeToRightOf(window, button, tip);
        assertThat(fitted.x + tip.width).isLessThanOrEqualTo(button.x);
        assertThat(new Rectangle(fitted.x, fitted.y, tip.width, tip.height).intersects(button)).isFalse();
    }
}
