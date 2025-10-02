from itertools import chain

import idaapi
import ida_kernwin
import ida_funcs
import ida_strlist

from yarka.adapter import YaraExtractor
from yarka.types import String
from yarka.extractor import RangeExtractor, FunctionExtractor
from yarka.yara import RuleBuilder, RulesetBuilder
from yarka import ui
from yarka import utils


# rule parameters
WRAP_CURLY_BRACE = False        # wrap curly brace on a new line
INDENT_HEADERS = False          # indent for 'meta', 'strings', 'condition'

# editor default settings
DEFAULT_SHOW_COMMENTS = True    # show comments (checkbox)
DEFAULT_STRICT_RULE = False     # don't wildcard relative offsets (checkbox)
DEFAULT_INDENT = 2              # default indent

# values can be string or lambda
DEFAULT_META_FIELDS = {
    'description': '',
    'source': 'Internal research',
    'date': lambda: utils.get_current_time('%Y-%m-%d'),
    'hash': lambda: utils.get_file_md5(),
    # 'hash': lambda: utils.get_file_sha256(),
}

# values can be string or lambda (optional argument - strings count)
DEFAULT_CONDITIONS = [
    lambda: '(PE)' in idaapi.get_file_type_name() and 'uint16(0) == 0x5A4D',
    lambda: 'ELF' in idaapi.get_file_type_name() and 'uint32(0) == 0x464C457F',
    lambda count: f'{count // 2} of them' if count > 2 else 'all of them'
]


def generate_rule(name, entities) -> RuleBuilder:
    rule = RuleBuilder(
        name,
        indent_headers=INDENT_HEADERS,
        wrap_curly_brace=WRAP_CURLY_BRACE,
    )

    for header, value in DEFAULT_META_FIELDS.items():
        rule.add_meta(header, value)
    
    existing = set()
    for i, entity in enumerate(entities, start=1):
        if str(entity) not in existing:
            rule.add_string(f's{i}', entity)
            existing.add(str(entity))

    for condition in DEFAULT_CONDITIONS:
        rule.add_condition(condition)

    return rule


class YaraDialog(ui.ClosableDialog):
    def __init__(self, rule: RuleBuilder):
        self.rule = rule

        self.strict_checkbox = ui.Checkbox(
            label='strict',
            default=DEFAULT_STRICT_RULE,
            on_click=self.handle_strict_checkbox_click,
        )
        self.comments_checkbox = ui.Checkbox(
            label='show comments',
            default=DEFAULT_SHOW_COMMENTS,
            on_click=self.handle_comments_checkbox_click,
        )
        self.indent_edit_label = ui.Label('indentation')
        self.indent_edit = ui.NumberInput(
            default=DEFAULT_INDENT,
            min_value=2,
            max_value=8,
            step=2,
            on_change=self.handle_indent_change,
        )
        self.text_edit = ui.YaraTextEdit(rule.build())

        super().__init__(
            title = 'Yarka - Generated Yara Rule',
            width=800,
            top_left_items=[self.strict_checkbox, self.comments_checkbox],
            top_right_items=[self.indent_edit_label, self.indent_edit],
            body_items=[self.text_edit]
        )

    def _rebuild_rule(self):
        content = self.rule.build()
        self.text_edit.set_content(content)

    def handle_strict_checkbox_click(self):
        self.rule.strict = self.strict_checkbox.is_checked()
        self._rebuild_rule()

    def handle_comments_checkbox_click(self):
        self.rule.show_comments = self.comments_checkbox.is_checked()
        self._rebuild_rule()

    def handle_indent_change(self):
        self.rule.indent = self.indent_edit.value()
        self._rebuild_rule()


class YarkaPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = 'Yarka Plugin'
    help = 'Yarka Plugin'
    wanted_name = 'Yarka'
    wanted_hotkey = 'Ctrl+Alt+Y'
    banner = (
        r" __     __        _         "
        r" \ \   / /       | |        "
        r"  \ \_/ /_ _ _ __| | ____ _ "
        r"   \   / _` | '__| |/ / _` |"
        r"    | | (_| | |  |   < (_| |"
        r"    |_|\__,_|_|  |_|\_\__,_|"
        r"                            "
    )

    def init(self):
        self.ui_hooks = YarkaUIHooks()
        self.ui_hooks.hook()

        label = 'Yarka: Generate Rule'
        hotkey = 'Ctrl+Y'
        YarkaRule.register(self, label, hotkey)
        YarkaStrings.register(self, label, hotkey)
        YarkaFunctions.register(self, label, hotkey)

        idaapi.msg(f'[{self.wanted_name}] loaded, hotkey - {self.wanted_hotkey}')
        return idaapi.PLUGIN_KEEP

    def term(self):
        self.ui_hooks.unhook()

    def run(self, arg):
        ida_kernwin.show_wait_box('Generating ruleset ...')

        ruleset = RulesetBuilder()
        functions = list(utils.get_custom_functions())
        for i, function in enumerate(functions, start=1):
            if ida_kernwin.user_cancelled():
                ida_kernwin.hide_wait_box()
                ida_kernwin.warning('Yarka - ruleset generation canceled')
                return None

            ida_kernwin.replace_wait_box(f'Processing ({i}/{len(functions)})')

            try:
                name = ida_funcs.get_func_name(function.start_ea)
                entities = YaraExtractor(FunctionExtractor(function.start_ea))
                rule = generate_rule(name=name, entities=list(entities))
                if not rule.is_empty():
                    ruleset.append(rule)
            except Exception as e:
                ida_kernwin.warning(f'Yarka - unexpected error {e}')

        ida_kernwin.replace_wait_box(f'Building ruleset ...')

        self.dialog = YaraDialog(ruleset)
        self.dialog.show()
        ida_kernwin.hide_wait_box()


class YarkaRule(ui.ActionHandler):
    __windows__ = [idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE]

    def activate(self, ctx):
        start, end = utils.get_selection()
        name = f'{utils.get_file_name()}_0x{start:08X}'
        entities = YaraExtractor(RangeExtractor(start, end))
        rule = generate_rule(name=name, entities=entities)

        self.dialog = YaraDialog(rule)
        self.dialog.show()


class YarkaStrings(ui.ActionHandler):
    __windows__ = [idaapi.BWN_STRINGS]

    def activate(self, ctx):
        strings = []
        for idx in ctx.chooser_selection:
            si = ida_strlist.string_info_t()
            if not ida_strlist.get_strlist_item(si, idx):
                continue

            string_gen = YaraExtractor([String.from_string_info(si)])
            strings.append(string_gen)
        
        name = f'{utils.get_file_name()}_strings'
        entities = chain.from_iterable(strings)
        rule = generate_rule(name=name, entities=entities)

        self.dialog = YaraDialog(rule)
        self.dialog.show()


class YarkaFunctions(ui.ActionHandler):
    __windows__ = [idaapi.BWN_FUNCS]

    def activate(self, ctx):
        ruleset = RulesetBuilder()
        for idx in ctx.chooser_selection:
            _, _, location, *_ = ida_kernwin.get_chooser_data(ctx.widget_title, idx)
            address = int(location.lstrip('0'), 16)

            name = ida_funcs.get_func_name(address)
            if not name:
                continue

            entities = YaraExtractor(FunctionExtractor(address))
            rule = generate_rule(name=name, entities=list(entities))
            if not rule.is_empty():
                ruleset.append(rule)

        self.dialog = YaraDialog(ruleset)
        self.dialog.show()


class YarkaUIHooks(idaapi.UI_Hooks):
    def populating_widget_popup(self, form, popup):
        pass

    def finish_populating_widget_popup(self, form, popup):
        YarkaRule.attach_ctx_menu(form, popup, 'Yarka')
        YarkaStrings.attach_ctx_menu(form, popup, 'Yarka')
        YarkaFunctions.attach_ctx_menu(form, popup, 'Yarka')


plugin = YarkaPlugin()


def PLUGIN_ENTRY():
    global plugin
    return plugin
