import idaapi
import ida_kernwin


class ActionHandler(idaapi.action_handler_t):
    __windows__: list = []

    @classmethod
    def get_name(cls):
        return cls.__name__

    @classmethod
    def get_label(cls):
        return cls.label

    @classmethod
    def register(cls, plugin, label, hotkey=None):
        cls.plugin = plugin
        cls.label = label
        instance = cls()

        action = idaapi.action_desc_t(
            cls.get_name(), 
            instance.get_label(), 
            instance, 
            hotkey,
        )

        return idaapi.register_action(action)

    @classmethod
    def unregister(cls):
        idaapi.unregister_action(cls.get_name())

    @classmethod
    def update(cls, ctx):
        if hasattr(cls, "__windows__") and ctx.widget_type in cls.__windows__:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET

        return ida_kernwin.AST_DISABLE_FOR_WIDGET

    @classmethod
    def attach_ctx_menu(cls, form, popup, tree: str):
        tft = idaapi.get_widget_type(form)
        if tft in cls.__windows__:
            idaapi.attach_action_to_popup(
                form, popup, cls.get_name(), tree, idaapi.SETMENU_APP
            )
