package ai.anomalousvectors.tools.burp.ui.primitives;

import java.awt.AWTEvent;
import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serial;

import javax.swing.AbstractAction;
import javax.swing.ActionMap;
import javax.swing.ButtonModel;
import javax.swing.Icon;
import javax.swing.JCheckBox;
import javax.swing.JToolTip;
import javax.swing.SwingUtilities;
import javax.swing.ToolTipManager;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.plaf.ActionMapUIResource;

import ai.anomalousvectors.tools.burp.ui.text.Tooltips;

/**
 * Tri-state checkbox for parent/child selection UIs.
 *
 * <p>Based on the robust model approach described by Heinz Kabutz (TristateCheckBox Revisited),
 * adapted so user interaction toggles only between SELECTED and DESELECTED; INDETERMINATE is
 * set programmatically.</p>
 *
 * <p>Caller must invoke on the EDT for construction and UI mutation. Transient listeners and
 * action bindings are rebuilt after deserialization and attachment to the component hierarchy.</p>
 */
public final class TriStateCheckBox extends JCheckBox {

    @Serial private static final long serialVersionUID = 1L;

    /** Logical selection states, including a programmatic mixed-child state. */
    public enum State {
        SELECTED,
        INDETERMINATE,
        DESELECTED
    }

    /**
     * Maps logical selection onto Swing's selected, armed, and pressed flags.
     *
     * <p>Caller must invoke on the EDT when this model is attached to a component.</p>
     */
    public static final class TriStateButtonModel extends javax.swing.JToggleButton.ToggleButtonModel {
        @Serial private static final long serialVersionUID = 1L;

        private State state = State.DESELECTED;

        /**
         * Creates a model with the requested logical state.
         *
         * @param initial initial state; {@code null} selects {@link State#DESELECTED}
         */
        public TriStateButtonModel(State initial) {
            setState(initial == null ? State.DESELECTED : initial);
        }

        /**
         * Updates the logical state, refreshes Swing flags, and notifies change listeners.
         *
         * @param s requested state; {@code null} selects {@link State#DESELECTED}
         */
        public void setState(State s) {
            this.state = s == null ? State.DESELECTED : s;
            displayState();
            fireStateChanged();
        }

        /** Returns the current non-null logical selection state. */
        public State getState() {
            return state;
        }

        /** Returns whether the model represents a mixed child selection. */
        public boolean isIndeterminate() {
            return state == State.INDETERMINATE;
        }

        /** Selects the programmatic mixed-child state and notifies change listeners. */
        public void setIndeterminate() {
            setState(State.INDETERMINATE);
        }

        @Override
        public void setSelected(boolean selected) {
            setState(selected ? State.SELECTED : State.DESELECTED);
        }

        void toggleSelected() {
            if (state == State.SELECTED) {
                setState(State.DESELECTED);
            } else {
                setState(State.SELECTED);
            }
        }

        private void displayState() {
            super.setSelected(state != State.DESELECTED);
            super.setArmed(state == State.INDETERMINATE);
            super.setPressed(state == State.INDETERMINATE);
        }
    }

    private transient ChangeListener enableListener;
    private transient boolean uiBehaviorInstalled;
    private transient MouseListener triStateMouseListener;

    private ChangeListener enableListener() {
        if (enableListener == null) {
            enableListener = (ChangeEvent e) -> TriStateCheckBox.this.setFocusable(getModel().isEnabled());
        }
        return enableListener;
    }

    /**
     * Creates a checkbox with the standard tri-state icon.
     *
     * @param text checkbox label
     * @param initial initial state; {@code null} selects {@link State#DESELECTED}
     */
    public TriStateCheckBox(String text, State initial) {
        this(text, null, initial);
    }

    /**
     * Creates a checkbox with a tri-state model and an optional custom icon.
     *
     * @param text checkbox label
     * @param icon custom icon; {@code null} installs the standard tri-state icon
     * @param initial initial state; {@code null} selects {@link State#DESELECTED}
     */
    public TriStateCheckBox(String text, Icon icon, State initial) {
        super(text, icon);
        putClientProperty("html.disable", Boolean.FALSE);
        setModel(new TriStateButtonModel(initial));
        if (icon == null) {
            setIcon(new TriStateCheckBoxIcon());
        }
    }

    @Override
    public JToolTip createToolTip() {
        return Tooltips.createHtmlToolTip(this);
    }

    /**
     * Updates selection through the installed tri-state model.
     *
     * @param state requested state; {@code null} selects {@link State#DESELECTED}
     */
    public void setState(State state) {
        getTriStateModel().setState(state);
    }

    /** Returns the installed model's non-null logical selection state. */
    public State getState() {
        return getTriStateModel().getState();
    }

    /** Displays a mixed child selection without adding it to the user-toggle cycle. */
    public void setIndeterminate() {
        getTriStateModel().setIndeterminate();
    }

    /** Returns whether the checkbox displays a mixed child selection. */
    public boolean isIndeterminate() {
        return getTriStateModel().isIndeterminate();
    }

    @Override
    public void setModel(ButtonModel newModel) {
        super.setModel(newModel);
        if (model instanceof TriStateButtonModel) {
            model.addChangeListener(enableListener());
        }
    }

    @Serial
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        uiBehaviorInstalled = false;
        triStateMouseListener = null;
        if (model instanceof TriStateButtonModel) {
            model.addChangeListener(enableListener());
        }
    }

    @Override
    public void addNotify() {
        super.addNotify();
        installUiBehavior();
    }

    // Prevent external mouse listeners from interfering with tri-state behaviour.
    @Override
    public void addMouseListener(MouseListener l) {
        if (l instanceof ToolTipManager) {
            super.addMouseListener(l);
        }
    }

    /**
     * Returns the installed tri-state model.
     *
     * @return model used for logical selection and mixed-state rendering
     * @throws ClassCastException if a caller replaced the model with another model type
     */
    public TriStateButtonModel getTriStateModel() {
        return (TriStateButtonModel) super.getModel();
    }

    private void toggle() {
        if (!getModel().isEnabled()) {
            return;
        }
        grabFocus();
        getTriStateModel().toggleSelected();

        int modifiers = 0;
        AWTEvent currentEvent = EventQueue.getCurrentEvent();
        switch (currentEvent) {
            case InputEvent ie -> modifiers = ie.getModifiersEx();
            case ActionEvent ae -> modifiers = ae.getModifiers();
            default -> { }
        }
        fireActionPerformed(new ActionEvent(this,
                ActionEvent.ACTION_PERFORMED, getText(),
                System.currentTimeMillis(), modifiers));
    }

    private void installUiBehavior() {
        if (uiBehaviorInstalled) {
            return;
        }
        triStateMouseListener = new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                toggle();
            }
        };
        super.addMouseListener(triStateMouseListener);

        ActionMap actions = new ActionMapUIResource();
        actions.put("pressed", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                toggle();
            }
        });
        actions.put("released", null);
        SwingUtilities.replaceUIActionMap(this, actions);
        uiBehaviorInstalled = true;
    }
}
